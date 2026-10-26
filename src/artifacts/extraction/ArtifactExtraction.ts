import type { AsarHeaderAdmission } from "../../config/asarHeaderAdmission.js";
import { resolveAsarHeaderAdmission } from "../AsarHeader.js";
import { locateGodotPck } from "../GodotPckLocation.js";
import { withArtifactRegularFile } from "../ArtifactFileOperation.js";
import type {
  ArtifactCleanupAttempt,
  ArtifactResourceOwner,
  ArtifactResourceScope,
} from "../ArtifactResourceScope.js";
import { lstat, realpath } from "node:fs/promises";
import { dirname } from "node:path";
import { absoluteCallerPath } from "../../filesystem/callerPath.js";
import { isPathWithinRoot } from "../../domain/localPath.js";
import { SafeOutputTreeDestinationRefusal } from "../SafeOutputTreeAdmission.js";

import { compareUnicodeCodePoints } from "../../domain/unicodeCodePointOrder.js";
import { digestCanonicalValue } from "../../domain/canonicalDigest.js";
import { AsarArtifactReader } from "../AsarArtifactReader.js";
import { GodotPckArtifactReader } from "../GodotPckArtifactReader.js";
import {
  ArtifactPathRegistry,
  destinationCaseCollisions,
  normalizeArtifactPath,
  type DestinationCaseSensitivity,
} from "../ArtifactPaths.js";
import {
  ArtifactReaderFailure,
  type ArtifactEntry,
  type ArtifactReader,
  type ArtifactReaderTraversal,
} from "../ArtifactReader.js";
import { ArtifactTraversalObservation } from "../ArtifactTraversalObservation.js";
import { abortIfNeeded } from "../ArtifactHash.js";
import { DirectoryArtifactReader } from "../DirectoryArtifactReader.js";
import { SafeOutputTree, normalizeDestinationPath } from "../SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../SafeOutputTreeCreationFailure.js";
import { ZipArtifactReader } from "../ZipArtifactReader.js";
import { isZipPackageFormat } from "../../domain/zipPackageFormat.js";
import { MachOSliceArtifactReader } from "../MachOSliceArtifactReader.js";
import { NodeSeaArtifactReader } from "../NodeSeaArtifactReader.js";
import { PyInstallerArtifactReader } from "../PyInstallerArtifactReader.js";
import { containsPyInstallerArchive } from "../pyinstaller/CArchiveLayout.js";
import { locateNodeSea } from "../nodeSea/NodeSeaLocation.js";
import {
  artifactExtractionResultSchema,
  type ArtifactExtractionPlan,
  type ArtifactExtractionPlanEntry,
  type ArtifactExtractionResult,
  type ArtifactGraphManifest,
  type ArtifactCommand,
  type ArtifactNode,
  type ArtifactOccurrence,
} from "../../domain/artifactGraph.js";
import { AnalysisUnsupportedTargetError } from "../../domain/analysisErrorCore.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import type { ArtifactInventorySnapshot } from "../../domain/artifactInventorySnapshot.js";
import { scanArtifactInventoryForExtractionInScope } from "../inventory/ArtifactInventory.js";
import type { TransferredZipInventorySource } from "../inventory/scanCanonical.js";
import type { ArtifactIntegrityPolicyName } from "../../domain/artifactIntegrityPolicy.js";

/** Local extraction input with the output root chosen by the adapter. */
export interface ArtifactExtractionInput {
  readonly asarHeaderAdmission?: AsarHeaderAdmission;
  readonly inputPath: string;
  readonly inputFormat: BinaryTarget["format"];
  readonly outputRoot: string;
  readonly dryRun?: boolean;
  readonly platform?: NodeJS.Platform;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly integrityPolicy: ArtifactIntegrityPolicyName;
  readonly resourceScope: ArtifactResourceScope;
}

/** Extract every regular inventory occurrence into an exclusively owned absent root. */
export const extractArtifact = async (
  input: ArtifactExtractionInput,
  signal?: AbortSignal,
): Promise<ArtifactExtractionResult> =>
  input.resourceScope.run(() => extractArtifactInScope(input, signal));

const extractArtifactInScope = async (
  input: ArtifactExtractionInput,
  signal?: AbortSignal,
): Promise<ArtifactExtractionResult> => {
  // Cancellation wins over every later refusal, including unsupported formats.
  abortIfNeeded(signal);
  const sourcePath = await realpath(input.inputPath);
  await requireExtractableFormat(sourcePath, input, signal);
  const { snapshot, zipSource } =
    await scanArtifactInventoryForExtractionInScope(sourcePath, {
      resourceScope: input.resourceScope,
      signal,
      environment: input.environment,
      asarHeaderAdmission:
        input.asarHeaderAdmission ??
        resolveAsarHeaderAdmission(input.environment),
      integrity: { mode: input.integrityPolicy },
    });
  const activeZipSource =
    zipSource === undefined
      ? undefined
      : { ...zipSource, releaseAttempted: false };
  try {
    return await materializeArtifactInventoryInScope(
      input,
      sourcePath,
      snapshot,
      signal,
      activeZipSource,
    );
  } catch (cause: unknown) {
    if (activeZipSource !== undefined && cause instanceof ArtifactReaderFailure)
      cause.retainPartialObservation({
        kind: "artifact-inventory",
        inventory: snapshot,
      });
    const attempt = await releaseTransferredZipSource(
      input.resourceScope,
      activeZipSource,
    );
    if (attempt?.kind === "failed")
      throw input.resourceScope.cleanupFailure(
        { kind: "failed", cause },
        [attempt],
        { kind: "artifact-inventory", inventory: snapshot },
      );
    throw cause;
  }
};

interface ActiveZipInventorySource extends TransferredZipInventorySource {
  releaseAttempted: boolean;
}

const releaseTransferredZipSource = async (
  resourceScope: ArtifactResourceScope,
  zipSource: ActiveZipInventorySource | undefined,
): Promise<ArtifactCleanupAttempt | undefined> => {
  if (zipSource === undefined || zipSource.releaseAttempted) return undefined;
  zipSource.releaseAttempted = true;
  return resourceScope.release(zipSource.owner);
};

/** Materialize a scanned inventory, borrowing its active ZIP source when supplied. */
export const materializeArtifactInventoryInScope = async (
  input: ArtifactExtractionInput,
  sourcePath: string,
  snapshot: ArtifactInventorySnapshot,
  signal?: AbortSignal,
  zipSource?: ActiveZipInventorySource,
): Promise<ArtifactExtractionResult> => {
  abortIfNeeded(signal);
  // A directory source must never acquire its own output as a new member on
  // the verification traversal. Resolve the selected parent before any write.
  if (zipSource === undefined) {
    const canonicalSource = await realpath(sourcePath);
    if ((await lstat(canonicalSource)).isDirectory()) {
      const parent = await realpath(
        dirname(absoluteCallerPath(input.outputRoot)),
      );
      if (isPathWithinRoot(canonicalSource, parent))
        throw new SafeOutputTreeDestinationRefusal(
          `Extraction output parent ${parent} is inside source directory ${canonicalSource}. Choose a temporary directory outside the source.`,
        );
    }
  }
  abortIfNeeded(signal);
  const containerMetadata = snapshot.occurrences.find(
    (row) => row.logical_path === ".",
  )?.format_metadata;
  if (
    containerMetadata?.kind === "godot-pck" &&
    containerMetadata.directory_status !== "available"
  )
    throw new AnalysisUnsupportedTargetError(
      "extract_artifact",
      input.inputPath,
      `Godot PCK directory is ${containerMetadata.directory_status}; its complete contents cannot be extracted`,
    );
  const selectedOccurrences = snapshot.occurrences.filter(
    (occurrence) =>
      (occurrence.entry_kind === "file" || occurrence.entry_kind === "slice") &&
      occurrence.logical_path !== ".",
  );
  const regularPaths = new Set(
    selectedOccurrences.map(({ logical_path: path }) => path),
  );
  const directoryPaths = new Set(
    snapshot.occurrences
      .filter(({ entry_kind }) => entry_kind === "directory")
      .map(({ logical_path }) => logical_path),
  );
  const activeOccurrences = selectedOccurrences.filter(({ logical_path }) => {
    // Nested members remain represented by their containing regular file;
    // only entries exposed by the active reader are materialized.
    let path = logical_path;
    for (
      let slash = path.lastIndexOf("/");
      slash >= 0;
      slash = path.lastIndexOf("/")
    ) {
      path = path.slice(0, slash);
      if (regularPaths.has(path) && !directoryPaths.has(path)) return false;
    }
    return true;
  });
  const neededNodes = new Set(
    activeOccurrences.map(({ artifact_id: id }) => id),
  );
  const nodes = new Map<string, ArtifactNode>();
  for (const node of snapshot.nodes)
    if (neededNodes.has(node.artifact_id)) nodes.set(node.artifact_id, node);
  const selected = activeOccurrences.map((occurrence) => {
    // REA never decrypts archive entries, so an encrypted entry makes the
    // complete extraction unsupported rather than the archive invalid.
    if (occurrence.encrypted)
      throw new AnalysisUnsupportedTargetError(
        "extract_artifact",
        input.inputPath,
        `Archive entry ${occurrence.logical_path} is encrypted; REA does not decrypt archive entries, so the archive cannot be extracted completely`,
      );
    // Inventory retains unavailable source occurrences, but extraction cannot
    // materialize bytes it never observed.
    if (
      occurrence.entry_kind === "file" &&
      occurrence.artifact_id === null &&
      occurrence.hash_status === "unavailable"
    )
      throw new ArtifactReaderFailure(
        "unavailable",
        `Inventoried source bytes are unavailable for ${occurrence.logical_path}`,
        undefined,
        occurrence.unpacked === true
          ? {
              logicalPath: occurrence.logical_path,
              declaredSha256: null,
              calculatedSha256: null,
              unpacked: true,
            }
          : undefined,
      );
    if (
      (occurrence.entry_kind !== "file" && occurrence.entry_kind !== "slice") ||
      occurrence.artifact_id === null ||
      occurrence.logical_path === "."
    )
      throw new ArtifactReaderFailure(
        "format",
        `Selected occurrence is not an extractable regular child file: ${occurrence.logical_path} (${occurrence.occurrence_id})`,
      );
    const node = nodes.get(occurrence.artifact_id);
    if (node === undefined)
      throw new ArtifactReaderFailure(
        "integrity",
        `Selected occurrence has no inventory node: ${occurrence.occurrence_id}`,
      );
    return { occurrence, node };
  });
  return materializeSelection({
    input,
    sourcePath,
    inventory: snapshot,
    selected,
    signal,
    zipSource,
  });
};

interface SelectedOccurrence {
  readonly occurrence: ArtifactOccurrence;
  readonly node: ArtifactNode;
}

interface ExtractedOccurrence {
  readonly artifact_id: string;
  readonly relative_path: string;
  readonly sha256: string;
  readonly bytes_written: number;
  readonly created: boolean;
}

const materializeSelection = async ({
  input,
  sourcePath,
  inventory,
  selected,
  signal,
  zipSource,
}: {
  readonly input: ArtifactExtractionInput;
  readonly sourcePath: string;
  readonly inventory: ArtifactInventorySnapshot;
  readonly selected: readonly SelectedOccurrence[];
  readonly signal: AbortSignal | undefined;
  readonly zipSource: ActiveZipInventorySource | undefined;
}): Promise<ArtifactExtractionResult> => {
  const byPath = new Map<string, SelectedOccurrence>();
  for (const item of selected) {
    const path = item.occurrence.logical_path;
    if (byPath.has(path))
      throw new ArtifactReaderFailure(
        "path",
        `Artifact extraction path collision: ${JSON.stringify(path)}. Multiple selected occurrences share this normalized logical path; they cannot be materialized at the same destination path, even when the archive is valid. Inventory retains each occurrence.`,
      );
    byPath.set(path, item);
  }
  const reader = await createReader(
    sourcePath,
    input,
    inventory.manifest.root_format,
    signal,
    zipSource,
  );
  const readerOwner: ArtifactResourceOwner = {
    kind: "reader" as const,
    reader,
    resource: `artifact reader for ${sourcePath}`,
  };
  const dryRun = input.dryRun === true;
  let localReaderOwner: ArtifactResourceOwner | undefined = readerOwner;
  let output: SafeOutputTree | undefined;
  let completed: ArtifactExtractionResult | undefined;
  const extracted: ExtractedOccurrence[] = [];
  try {
    await reader.prepareContainer?.(inventory.manifest.root_sha256, signal);
    const platform = input.platform ?? process.platform;
    let destinationCaseSensitivity: DestinationCaseSensitivity =
      "case-sensitive";
    if (dryRun) {
      const destination = await SafeOutputTree.checkDestination(
        input.outputRoot,
        platform,
      );
      destinationCaseSensitivity = destination.caseSensitivity;
    } else {
      try {
        output = await SafeOutputTree.create(input.outputRoot, platform);
      } catch (cause: unknown) {
        if (cause instanceof SafeOutputTreeCreationFailure) output = cause.tree;
        throw cause;
      }
    }
    const traversal = new ArtifactTraversalObservation();
    traversal.onCoverage({
      status: inventory.coverage.status,
      limitations: inventory.limitations,
    });
    let unresolvedCaseReasons: ReadonlyMap<string, string> = new Map();
    if (dryRun) {
      unresolvedCaseReasons = await planSelectedEntries({
        reader,
        platform,
        caseSensitivity: destinationCaseSensitivity,
        byPath,
        extracted,
        traversal,
        signal,
      });
    } else {
      await writeSelectedEntries({
        reader,
        output: output!,
        byPath,
        extracted,
        traversal,
        signal,
      });
    }
    localReaderOwner = undefined;
    const closeAttempt = await input.resourceScope.release(readerOwner);
    if (closeAttempt.kind === "failed")
      throw input.resourceScope.cleanupFailure(
        { kind: "completed" },
        [closeAttempt],
        { kind: "artifact-inventory", inventory },
      );
    const sourceClose = await releaseTransferredZipSource(
      input.resourceScope,
      zipSource,
    );
    if (sourceClose?.kind === "failed")
      throw input.resourceScope.cleanupFailure(
        { kind: "completed" },
        [sourceClose],
        { kind: "artifact-inventory", inventory },
      );
    abortIfNeeded(signal);
    extracted.sort((left, right) =>
      compareUnicodeCodePoints(left.relative_path, right.relative_path),
    );
    completed = createExtractionResult(
      input,
      inventory,
      selected,
      extracted,
      traversal.snapshot(),
      reader.provenance(),
      unresolvedCaseReasons,
      destinationCaseSensitivity,
    );
    if (output !== undefined) await output.commit(signal);
    return completed;
  } catch (cause: unknown) {
    const cleanupFailures = await releaseExtractionOwners(
      input.resourceScope,
      localReaderOwner,
      output,
      input.outputRoot,
    );
    const [firstCleanup, ...remainingCleanup] = cleanupFailures;
    if (firstCleanup !== undefined) {
      throw input.resourceScope.cleanupFailure(
        { kind: "failed", cause },
        [firstCleanup, ...remainingCleanup],
        output?.published === true && completed !== undefined
          ? { kind: "artifact-extraction", extraction: completed }
          : undefined,
      );
    }
    if (output?.published === true && completed !== undefined) return completed;
    throw cause;
  }
};

const planSelectedEntries = async ({
  reader,
  platform,
  caseSensitivity,
  byPath,
  extracted,
  traversal,
  signal,
}: {
  readonly reader: ArtifactReader;
  readonly platform: NodeJS.Platform;
  readonly caseSensitivity: DestinationCaseSensitivity;
  readonly byPath: Map<string, SelectedOccurrence>;
  readonly extracted: ExtractedOccurrence[];
  readonly traversal: ArtifactTraversalObservation;
  readonly signal: AbortSignal | undefined;
}): Promise<ReadonlyMap<string, string>> => {
  const readerRegistry = new ArtifactPathRegistry();
  const outputRegistry = new ArtifactPathRegistry({
    caseInsensitive: caseSensitivity === "case-insensitive",
  });
  const staged: {
    readonly selectedItem: SelectedOccurrence;
    readonly destinationPath: string;
  }[] = [];
  for await (const entry of reader.entries(signal, traversal)) {
    const path = normalizeArtifactPath(entry.path);
    readerRegistry.add(path, entry.kind);
    if (entry.kind !== "file" && entry.kind !== "slice") continue;
    const selectedItem = byPath.get(path);
    if (selectedItem === undefined) {
      throw new ArtifactReaderFailure(
        "integrity",
        `Regular artifact entry is missing from inventory: ${path}`,
      );
    }
    preflight(entry);
    if (
      !Number.isSafeInteger(selectedItem.node.size) ||
      selectedItem.node.size < 0
    )
      throw new ArtifactReaderFailure(
        "format",
        `Invalid expected extraction size for ${path}`,
      );
    const destinationPath = normalizeDestinationPath(path, platform);
    outputRegistry.add(destinationPath, "file");
    staged.push({ selectedItem, destinationPath });
    byPath.delete(path);
  }
  if (byPath.size > 0)
    throw new ArtifactReaderFailure(
      "integrity",
      `Inventoried regular artifact entries were not materialized: ${[...byPath.keys()].sort(compareUnicodeCodePoints).join(", ")}`,
    );
  const unresolvedByOccurrenceId = new Map<string, string>();
  const unresolvedCollisions =
    caseSensitivity === "case-sensitive"
      ? undefined
      : destinationCaseCollisions(
          staged.map(({ destinationPath }) => destinationPath),
        );
  for (const { selectedItem, destinationPath } of staged) {
    const collision = unresolvedCollisions?.get(destinationPath)?.[0];
    if (collision !== undefined) {
      unresolvedByOccurrenceId.set(
        selectedItem.occurrence.occurrence_id,
        caseSensitivity === "unknown"
          ? `Destination directory case sensitivity is unknown without creating files; case-colliding path ${collision.prefix} vs ${collision.other} cannot be verified as distinct during dry-run.`
          : `Destination filesystem case table for non-ASCII path ${collision.prefix} vs ${collision.other} is not observed without creating files; collision status remains unresolved during dry-run.`,
      );
      continue;
    }
    extracted.push({
      artifact_id: selectedItem.node.artifact_id,
      relative_path: destinationPath,
      sha256: selectedItem.node.sha256,
      bytes_written: 0,
      created: false,
    });
  }
  return unresolvedByOccurrenceId;
};

const createDryRunPlan = (
  inventory: ArtifactInventorySnapshot,
  selected: readonly SelectedOccurrence[],
  unresolvedCaseReasons: ReadonlyMap<string, string>,
): ArtifactExtractionPlan => {
  const selectedById = new Map(
    selected.map((item) => [item.occurrence.occurrence_id, item] as const),
  );
  const nodesById = new Map(
    inventory.nodes.map((node) => [node.artifact_id, node] as const),
  );
  const entries: ArtifactExtractionPlanEntry[] = [];
  let plannedFiles = 0;
  let unsupportedEntries = 0;
  let unresolvedEntries = 0;
  let observedBytesEstimate = 0;
  let declaredBytesEstimate: number | null = 0;
  for (const occurrence of inventory.occurrences) {
    if (occurrence.logical_path === ".") continue;
    const selectedItem = selectedById.get(occurrence.occurrence_id);
    if (selectedItem !== undefined) {
      const unresolvedReason = unresolvedCaseReasons.get(
        occurrence.occurrence_id,
      );
      if (unresolvedReason !== undefined) {
        unresolvedEntries += 1;
        entries.push({
          occurrence_id: occurrence.occurrence_id,
          logical_path: occurrence.logical_path,
          entry_kind: occurrence.entry_kind,
          status: "unresolved",
          reason: unresolvedReason,
          observed_bytes: selectedItem.node.size,
          declared_bytes: occurrence.declared_size,
        });
        continue;
      }
      plannedFiles += 1;
      observedBytesEstimate += selectedItem.node.size;
      if (occurrence.declared_size === null) declaredBytesEstimate = null;
      else if (declaredBytesEstimate !== null)
        declaredBytesEstimate += occurrence.declared_size;
      entries.push({
        occurrence_id: occurrence.occurrence_id,
        logical_path: occurrence.logical_path,
        entry_kind: occurrence.entry_kind,
        status: "planned",
        reason: null,
        observed_bytes: selectedItem.node.size,
        declared_bytes: occurrence.declared_size,
      });
      continue;
    }
    if (occurrence.entry_kind === "symlink") {
      unresolvedEntries += 1;
      entries.push({
        occurrence_id: occurrence.occurrence_id,
        logical_path: occurrence.logical_path,
        entry_kind: occurrence.entry_kind,
        status: "unresolved",
        reason:
          "Symlink entries are not materialized during extraction; target remains unresolved.",
        observed_bytes: null,
        declared_bytes: occurrence.declared_size,
      });
      continue;
    }
    unsupportedEntries += 1;
    const reason =
      occurrence.entry_kind === "directory"
        ? "Directory entries are not materialized directly; parent directories are created only as needed for planned regular files."
        : occurrence.entry_kind === "metadata"
          ? "Logical metadata declarations do not claim a destination file path."
          : "Nested archive member remains inside its containing regular file and is not expanded during single-container extraction.";
    const observedNode =
      occurrence.entry_kind === "directory" ||
      occurrence.entry_kind === "metadata" ||
      occurrence.artifact_id === null
        ? undefined
        : nodesById.get(occurrence.artifact_id);
    entries.push({
      occurrence_id: occurrence.occurrence_id,
      logical_path: occurrence.logical_path,
      entry_kind: occurrence.entry_kind,
      status: "unsupported",
      reason,
      observed_bytes:
        typeof observedNode?.size === "number" ? observedNode.size : null,
      declared_bytes: occurrence.declared_size,
    });
  }
  entries.sort(
    (left, right) =>
      compareUnicodeCodePoints(left.logical_path, right.logical_path) ||
      compareUnicodeCodePoints(left.occurrence_id, right.occurrence_id),
  );
  return {
    entries,
    totals: {
      planned_files: plannedFiles,
      unsupported_entries: unsupportedEntries,
      unresolved_entries: unresolvedEntries,
      observed_bytes_estimate: observedBytesEstimate,
      declared_bytes_estimate: declaredBytesEstimate,
      byte_totals_basis: "declared-and-observed-content-estimates",
      byte_totals_note:
        "Declared and observed byte totals are content-byte estimates from archive metadata and inventory hashing, not guaranteed filesystem or disk-block usage.",
    },
  };
};

const writeSelectedEntries = async ({
  reader,
  output,
  byPath,
  extracted,
  traversal,
  signal,
}: {
  readonly reader: ArtifactReader;
  readonly output: SafeOutputTree;
  readonly byPath: Map<string, SelectedOccurrence>;
  readonly extracted: ExtractedOccurrence[];
  readonly traversal: ArtifactTraversalObservation;
  readonly signal: AbortSignal | undefined;
}): Promise<void> => {
  const registry = new ArtifactPathRegistry();
  for await (const entry of reader.entries(signal, traversal)) {
    const path = normalizeArtifactPath(entry.path);
    registry.add(path, entry.kind);
    // Logical declarations may share a query path with a real file. They do
    // not consume that file's selection or participate in materialization.
    if (entry.kind !== "file" && entry.kind !== "slice") continue;
    const selectedItem = byPath.get(path);
    if (selectedItem === undefined) {
      throw new ArtifactReaderFailure(
        "integrity",
        `Regular artifact entry is missing from inventory: ${path}`,
      );
    }
    preflight(entry);
    const stream = await reader.open(entry, signal);
    const written = await output.write(
      path,
      stream,
      {
        sha256: selectedItem.node.sha256,
        bytes: selectedItem.node.size,
      },
      signal,
    );
    extracted.push({
      artifact_id: selectedItem.node.artifact_id,
      relative_path: written.relativePath,
      sha256: written.sha256,
      bytes_written: written.bytesWritten,
      created: true,
    });
    byPath.delete(path);
  }
  if (byPath.size > 0)
    throw new ArtifactReaderFailure(
      "integrity",
      `Inventoried regular artifact entries were not materialized: ${[...byPath.keys()].sort(compareUnicodeCodePoints).join(", ")}`,
    );
};

const releaseExtractionOwners = async (
  resourceScope: ArtifactResourceScope,
  readerOwner: ArtifactResourceOwner | undefined,
  output: SafeOutputTree | undefined,
  outputRoot: string,
): Promise<Extract<ArtifactCleanupAttempt, { readonly kind: "failed" }>[]> => {
  const failures: Extract<
    ArtifactCleanupAttempt,
    { readonly kind: "failed" }
  >[] = [];
  if (readerOwner !== undefined) {
    const attempt = await resourceScope.release(readerOwner);
    if (attempt.kind === "failed") failures.push(attempt);
  }
  if (output !== undefined) {
    const owner: ArtifactResourceOwner = {
      kind: "output-tree",
      tree: output,
      resource: outputRoot,
    };
    const attempt = await resourceScope.release(owner);
    if (attempt.kind === "failed") failures.push(attempt);
  }
  return failures;
};

const createExtractionResult = (
  input: ArtifactExtractionInput,
  inventory: ArtifactInventorySnapshot,
  selected: readonly SelectedOccurrence[],
  extracted: readonly ExtractedOccurrence[],
  traversal: ArtifactReaderTraversal,
  materializationProvenance: readonly ArtifactCommand[],
  unresolvedCaseReasons: ReadonlyMap<string, string> = new Map(),
  destinationCaseSensitivity: DestinationCaseSensitivity = "case-sensitive",
): ArtifactExtractionResult => {
  const selectedIds = new Set(
    selected.map(({ occurrence }) => occurrence.occurrence_id),
  );
  const integrityContradictions = inventory.integrity_contradictions.filter(
    ({ occurrence_id: id }) => selectedIds.has(id),
  );
  const extractionSemantic = {
    source_manifest_id: inventory.manifest.manifest_id,
    selected_occurrence_ids: selected
      .map(({ occurrence }) => occurrence.occurrence_id)
      .sort(compareUnicodeCodePoints),
    files_sha256: digestCanonicalValue(extracted, "Artifact"),
    output_root_alias: "$OUTPUT_ROOT" as const,
  };
  const dryRun = input.dryRun === true;
  return artifactExtractionResultSchema.parse({
    manifest: inventory.manifest,
    extraction_manifest: {
      ...extractionSemantic,
      extraction_id: `aex_${digestCanonicalValue(extractionSemantic, "Artifact")}`,
    },
    output_root: input.outputRoot,
    ...(dryRun
      ? {
          dry_run: true,
          plan: createDryRunPlan(inventory, selected, unresolvedCaseReasons),
        }
      : {}),
    artifacts: extracted,
    containment_verified: true,
    cleanup: { attempted: false, verified: true, residual_paths: [] },
    provenance: [...inventory.provenance, ...materializationProvenance],
    coverage: {
      ...inventory.coverage,
      status: traversal.status,
    },
    integrity_contradictions: integrityContradictions,
    limitations: [
      ...traversal.limitations,
      ...selected.flatMap(({ occurrence }) =>
        occurrence.limitations.map(
          (limitation) => `${occurrence.logical_path}: ${limitation}`,
        ),
      ),
      dryRun
        ? "Dry-run extraction validated destination admission, path collisions, and reader entries without creating destination files or directories."
        : traversal.status === "complete"
          ? "All regular files exposed by the active artifact reader were materialized."
          : "All inventoried regular files exposed by the active reader were materialized; source traversal coverage is unknown, so the output is not established as a complete source copy.",
      dryRun
        ? "Dry-run byte totals are declared and observed content-byte estimates, not guaranteed disk usage."
        : "Publication verifies the selected inventoried regular files; it does not establish complete content decoding.",
      ...(unresolvedCaseReasons.size === 0
        ? []
        : [
            destinationCaseSensitivity === "unknown"
              ? "Destination directory case sensitivity is unknown because the destination parent has no observable cased entry; case-colliding paths remain unresolved in the dry-run plan."
              : "Non-ASCII case-folding paths depend on the destination filesystem case table and cannot be verified without creating files; affected paths remain unresolved in the dry-run plan.",
          ]),
      ...(integrityContradictions.length === 0
        ? []
        : [
            `${String(integrityContradictions.length)} ${dryRun ? "planned" : "extracted"} file(s) contradict declared integrity metadata; their bytes are observed-untrusted.`,
          ]),
    ],
  });
};

/**
 * Refuse a format without an extraction reader before inventory work starts.
 * The target kind, not the host, is unsupported by extraction. The error keeps
 * the caller's spelling of the path; I/O uses the canonical path.
 */
const requireExtractableFormat = async (
  path: string,
  input: Pick<
    ArtifactExtractionInput,
    "inputPath" | "inputFormat" | "resourceScope"
  >,
  signal?: AbortSignal,
): Promise<boolean> => {
  const format = input.inputFormat;
  const directory = (await lstat(path)).isDirectory();
  // A thin Mach-O has no child entries of its own: inventory lists only its
  // root unless it carries an embedded pack, so it takes the same pack probe
  // as ELF and PE while only the universal container has a slice reader.
  if (
    !directory &&
    format !== "asar" &&
    format !== "godot-pck" &&
    format !== "mach-o-universal" &&
    !isZipPackageFormat(format)
  ) {
    const pack = await withArtifactRegularFile(
      path,
      input.resourceScope,
      signal,
      async ({ handle, initial }) => {
        const size = initial.size;
        if (await locateGodotPck(handle, size, signal)) return true;
        if (format !== "elf" && format !== "pe" && format !== "mach-o")
          return false;
        abortIfNeeded(signal);
        if (await locateNodeSea(handle, size, signal)) return true;
        abortIfNeeded(signal);
        const packaged = await containsPyInstallerArchive(handle, size, signal);
        abortIfNeeded(signal);
        return packaged;
      },
    );
    if (!pack)
      throw new AnalysisUnsupportedTargetError(
        "extract_artifact",
        input.inputPath,
        `Artifact format has no extraction reader: ${format}`,
      );
  }
  return directory;
};

const createReader = async (
  path: string,
  input: Pick<
    ArtifactExtractionInput,
    | "inputPath"
    | "inputFormat"
    | "environment"
    | "resourceScope"
    | "asarHeaderAdmission"
  >,
  containerFormat: ArtifactGraphManifest["root_format"],
  signal?: AbortSignal,
  zipSource?: ActiveZipInventorySource,
): Promise<ArtifactReader> => {
  if (zipSource !== undefined && isZipPackageFormat(containerFormat))
    return new ZipArtifactReader(
      path,
      containerFormat,
      undefined,
      zipSource.source,
    );
  const format = input.inputFormat;
  if (containerFormat === "godot-pck") return new GodotPckArtifactReader(path);
  if (containerFormat === "pyinstaller")
    return new PyInstallerArtifactReader(path);
  if (containerFormat === "node-sea") return new NodeSeaArtifactReader(path);
  if (await requireExtractableFormat(path, input, signal))
    return new DirectoryArtifactReader(path);
  if (format === "asar")
    return new AsarArtifactReader(path, {
      headerAdmission:
        input.asarHeaderAdmission ??
        resolveAsarHeaderAdmission(input.environment),
    });
  if (isZipPackageFormat(format)) return new ZipArtifactReader(path, format);
  return new MachOSliceArtifactReader(path, input.environment);
};

const preflight = (entry: ArtifactEntry): void => {
  if ((entry.kind !== "file" && entry.kind !== "slice") || entry.encrypted)
    throw new ArtifactReaderFailure(
      "format",
      `Selected artifact entry cannot be read: ${entry.path}`,
    );
};

import { access, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

import { ArtifactProvider } from "../../../../src/artifacts/ArtifactProvider.js";
import { artifactExtractionExecutionSchema } from "../../../../src/contracts/artifactToolContracts.js";
import {
  artifactExtractionResultSchema,
  artifactInventoryResultSchema,
} from "../../../../src/domain/artifactGraph.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";

describe("artifact extraction", () => {
  it("keeps committed files after the owning client closes", async () => {
    const root = await createTestTempDirectory("rea-extract-client-close-");
    const source = join(root, "source");
    await mkdir(source);
    await writeFile(join(source, "payload.txt"), "committed\n");
    const output = join(root, "output");
    const client = new ArtifactProvider(process.env).createClient(
      target(source, "directory"),
    );

    const result = await client.execute("extract_artifact", {
      output_root: output,
    });
    if (!result.ok) throw result.error;
    await client.close();
    expect(await readFile(join(output, "payload.txt"), "utf8")).toBe(
      "committed\n",
    );
  });

  it("extracts all regular occurrences through an exclusively owned output tree", async () => {
    const root = await createTestTempDirectory("rea-extract-");
    const source = join(root, "source");
    await mkdir(join(source, "assets"), { recursive: true });
    await writeFile(join(source, "assets", "selected.js"), "selected();\n");
    await writeFile(join(source, "assets", "ignored.js"), "ignored();\n");
    const targetValue = target(source, "directory");
    const graph = await inventory(targetValue);
    expect(
      graph.occurrences.some(
        ({ logical_path }) => logical_path === "assets/selected.js",
      ),
    ).toBe(true);
    const cancelledOutput = join(root, "cancelled-output");
    const controller = new AbortController();
    controller.abort();
    const cancelled = await new ArtifactProvider(process.env)
      .createClient(targetValue)
      .execute(
        "extract_artifact",
        artifactExtractionExecutionSchema.parse({
          output_root: cancelledOutput,
        }),
        { signal: controller.signal },
      );
    expect(cancelled).toMatchObject({
      ok: false,
      error: { _tag: "ArtifactOperationError", reason: "cancelled" },
    });
    await expect(access(cancelledOutput)).rejects.toThrow();
    const output = join(root, "output");
    const result = await new ArtifactProvider(process.env)
      .createClient(targetValue)
      .execute(
        "extract_artifact",
        artifactExtractionExecutionSchema.parse({
          output_root: output,
        }),
      );
    if (!result.ok) throw result.error;
    const firstExtraction = artifactExtractionResultSchema.parse(
      result.value.result,
    );
    expect(firstExtraction).toMatchObject({
      output_root: output,
      containment_verified: true,
      artifacts: expect.arrayContaining([
        expect.objectContaining({ relative_path: "assets/selected.js" }),
      ]),
      extraction_manifest: { output_root_alias: "$OUTPUT_ROOT" },
    });
    // artifacts names every extracted path; the Evidence does not repeat them.
    expect(result.value.locations).toEqual([]);
    expect(await readFile(join(output, "assets", "selected.js"), "utf8")).toBe(
      "selected();\n",
    );
    expect(await readFile(join(output, "assets", "ignored.js"), "utf8")).toBe(
      "ignored();\n",
    );

    const relocatedOutput = join(root, "relocated-output");
    const relocated = await new ArtifactProvider(process.env)
      .createClient(targetValue)
      .execute(
        "extract_artifact",
        artifactExtractionExecutionSchema.parse({
          output_root: relocatedOutput,
        }),
      );
    if (!relocated.ok) throw relocated.error;
    expect(
      artifactExtractionResultSchema.parse(relocated.value.result)
        .extraction_manifest,
    ).toEqual(firstExtraction.extraction_manifest);

    const second = await new ArtifactProvider(process.env)
      .createClient(targetValue)
      .execute(
        "extract_artifact",
        artifactExtractionExecutionSchema.parse({
          output_root: output,
        }),
      );
    expect(second).toMatchObject({
      ok: false,
      error: { _tag: "ArtifactOperationError", reason: "path" },
    });
    expect((await readdir(root)).sort()).toEqual([
      "output",
      "relocated-output",
      "source",
    ]);
  });
});

describe("artifact extraction dry-run", () => {
  it("supports dry_run extraction planning and refuses existing destinations without creating files", async () => {
    const root = await createTestTempDirectory("rea-extract-dry-run-boundary-");
    const source = join(root, "source");
    await mkdir(join(source, "nested"), { recursive: true });
    await writeFile(join(source, "nested", "item.txt"), "hello world\n");
    const targetValue = target(source, "directory");
    const plannedOutput = join(root, "planned-output");

    const dryResult = await new ArtifactProvider(process.env)
      .createClient(targetValue)
      .execute(
        "extract_artifact",
        artifactExtractionExecutionSchema.parse({
          output_root: plannedOutput,
          dry_run: true,
        }),
      );
    if (!dryResult.ok) throw dryResult.error;
    const parsedDry = artifactExtractionResultSchema.parse(
      dryResult.value.result,
    );
    expect(parsedDry.dry_run).toBe(true);
    expect(parsedDry.artifacts).toEqual([
      expect.objectContaining({
        relative_path: "nested/item.txt",
        bytes_written: 0,
        created: false,
      }),
    ]);
    expect(parsedDry.plan).toMatchObject({
      entries: [
        expect.objectContaining({
          logical_path: "nested",
          entry_kind: "directory",
          status: "unsupported",
        }),
        expect.objectContaining({
          logical_path: "nested/item.txt",
          entry_kind: "file",
          status: "planned",
          observed_bytes: 12,
          declared_bytes: 12,
        }),
      ],
      totals: {
        planned_files: 1,
        unsupported_entries: 1,
        unresolved_entries: 0,
        observed_bytes_estimate: 12,
        declared_bytes_estimate: 12,
        byte_totals_basis: "declared-and-observed-content-estimates",
      },
    });
    await expect(access(plannedOutput)).rejects.toThrow();
    expect(await readdir(root)).toEqual(["source"]);

    await mkdir(plannedOutput);
    const existingRefusal = await new ArtifactProvider(process.env)
      .createClient(targetValue)
      .execute(
        "extract_artifact",
        artifactExtractionExecutionSchema.parse({
          output_root: plannedOutput,
          dry_run: true,
        }),
      );
    expect(existingRefusal).toMatchObject({
      ok: false,
      error: { _tag: "ArtifactOperationError", reason: "path" },
    });
  });
});
const inventory = async (targetValue: BinaryTarget) => {
  const result = await new ArtifactProvider(process.env)
    .createClient(targetValue)
    .execute("inventory_artifact", {});
  if (!result.ok) throw result.error;
  return artifactInventoryResultSchema.parse(result.value.result);
};

const target = (
  path: string,
  format: Extract<BinaryTarget, { kind: "archive" }>["format"] | "directory",
): BinaryTarget => ({
  path,
  sourcePath: path,
  sha256: "0".repeat(64),
  kind: "archive",
  format: format === "directory" ? "asar" : format,
});

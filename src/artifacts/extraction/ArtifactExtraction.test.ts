import {
  link,
  mkdir,
  readFile,
  readdir,
  rename,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

import { TextReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { expect, it, vi } from "vitest";

import { asarHeaderBytes } from "../../../tests/fixtures/asarHeader.js";
import { DestinationCaseCollisionFailure } from "../ArtifactPaths.js";
import { ArtifactReaderFailure } from "../ArtifactReader.js";
import { ArtifactResourceScope } from "../ArtifactResourceScope.js";
import { OwnedFileHandle } from "../../filesystem/OwnedFileHandle.js";
import { openRegularFile } from "../../filesystem/RegularFile.js";
import { ZipArtifactReader } from "../ZipArtifactReader.js";
import { DirectoryArtifactReader } from "../DirectoryArtifactReader.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { extractArtifact } from "./ArtifactExtraction.js";

const zipBytes = async (content?: string): Promise<Buffer> => {
  const writer = new ZipWriter(new Uint8ArrayWriter());
  if (content !== undefined)
    await writer.add("member.txt", new TextReader(content));
  return Buffer.from(await writer.close());
};

const zipInput = (
  path: string,
  outputRoot: string,
  resourceScope: ArtifactResourceScope,
) => ({
  inputPath: path,
  inputFormat: "zip" as const,
  outputRoot,
  environment: {},
  integrityPolicy: "fail" as const,
  resourceScope,
});

/** Intercept only the exact admitted root owner, including its later retry. */
const watchZipRootClose = (
  scope: ArtifactResourceScope,
  path: string,
  close: (original: () => Promise<void>, attempt: number) => Promise<void>,
): { readonly attempts: () => number; readonly restore: () => void } => {
  const originalRelease = scope.release.bind(scope);
  let rootCloseSpy: { mockRestore(): void } | undefined;
  let attempts = 0;
  const releaseSpy = vi
    .spyOn(scope, "release")
    .mockImplementation(async (owner) => {
      if (
        owner.kind === "file-handle" &&
        owner.resource === `root artifact descriptor for ${path}`
      ) {
        const originalClose = owner.handle.close.bind(owner.handle);
        rootCloseSpy = vi
          .spyOn(owner.handle, "close")
          .mockImplementation(() => close(originalClose, ++attempts));
      }
      return originalRelease(owner);
    });
  return {
    attempts: () => attempts,
    restore: () => {
      rootCloseSpy?.mockRestore();
      releaseSpy.mockRestore();
    },
  };
};

it.each(["archive", "directory", "missing"] as const)(
  "extracts from the inventoried ZIP descriptor when its pathname becomes %s",
  async (replacement) => {
    const directory = await createTestTempDirectory(
      "rea-zip-extraction-identity-",
    );
    const path = join(directory, "source.zip");
    const original = await zipBytes("unchanged");
    await writeFile(path, original);
    const output = join(directory, "out");
    const resourceScope = new ArtifactResourceScope();
    const open = vi.mocked(openRegularFile);
    open.mockClear();
    const directoryEntries = vi.spyOn(
      DirectoryArtifactReader.prototype,
      "entries",
    );
    const originalClose = ZipArtifactReader.prototype.close;
    let closes = 0;
    const close = vi
      .spyOn(ZipArtifactReader.prototype, "close")
      .mockImplementation(async function (this: ZipArtifactReader) {
        await originalClose.call(this);
        if (++closes !== 1) return;
        await rename(path, join(directory, "original.zip"));
        if (replacement === "directory") await mkdir(path);
        if (replacement === "archive") {
          // EOCD comment changes the carrier digest while every member stays identical.
          const changed = Buffer.from(original);
          changed.writeUInt16LE(1, changed.length - 2);
          await writeFile(path, Buffer.concat([changed, Buffer.from("B")]));
        }
      });
    try {
      const outcome = await extractArtifact(
        zipInput(path, output, resourceScope),
      )
        .then((result) => ({ kind: "completed" as const, result }))
        .catch((cause: unknown) => ({ kind: "failed" as const, cause }));
      if (outcome.kind === "failed") {
        // Renaming the admitted inode can change its ctime. Refusal is valid;
        // reading the replacement carrier or directory is not.
        expect(outcome.cause).toMatchObject({ reason: "integrity" });
        await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
      } else {
        expect(outcome.result.manifest.root_format).toBe("zip");
        expect(outcome.result.artifacts).toMatchObject([
          { relative_path: "member.txt" },
        ]);
        expect(await readFile(join(output, "member.txt"), "utf8")).toBe(
          "unchanged",
        );
      }
      expect(open).toHaveBeenCalledTimes(1);
      expect(directoryEntries).not.toHaveBeenCalled();
      expect(closes).toBe(2);
    } finally {
      close.mockRestore();
      directoryEntries.mockRestore();
      await resourceScope.close();
    }
  },
);

it("preserves cancellation raised during final ZIP descriptor close", async () => {
  const directory = await createTestTempDirectory("rea-zip-extraction-cancel-");
  const path = join(directory, "empty.zip");
  const bytes = await zipBytes();
  await writeFile(path, bytes);
  const digest = createHash("sha256").update(bytes).digest("hex");
  const output = join(directory, "out");
  const resourceScope = new ArtifactResourceScope();
  const controller = new AbortController();
  const reason = new Error("cancel during root close");
  let readerCloses = 0;
  const originalReaderClose = ZipArtifactReader.prototype.close;
  const readerClose = vi
    .spyOn(ZipArtifactReader.prototype, "close")
    .mockImplementation(async function (this: ZipArtifactReader) {
      readerCloses += 1;
      await originalReaderClose.call(this);
    });
  let outputExistedAtRootClose = false;
  let readerClosesAtRootClose = 0;
  const rootClose = watchZipRootClose(resourceScope, path, async (original) => {
    outputExistedAtRootClose = await stat(output).then(
      () => true,
      () => false,
    );
    readerClosesAtRootClose = readerCloses;
    controller.abort(reason);
    await original();
  });
  try {
    await expect(
      extractArtifact(zipInput(path, output, resourceScope), controller.signal),
    ).rejects.toMatchObject({
      reason: "cancelled",
      cause: reason,
      partialObservation: {
        kind: "artifact-inventory",
        inventory: {
          manifest: { root_format: "zip", root_sha256: digest },
          coverage: { scope: "container-entries", status: "complete" },
        },
      },
    });
    await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
    expect(outputExistedAtRootClose).toBe(true);
    expect(readerClosesAtRootClose).toBe(2);
    expect(rootClose.attempts()).toBe(1);
    expect(resourceScope.hasPending).toBe(false);
  } finally {
    await resourceScope.close();
    rootClose.restore();
    readerClose.mockRestore();
  }
});

it("retains completed ZIP inventory when cancellation arrives during inventory reader close", async () => {
  const directory = await createTestTempDirectory(
    "rea-zip-inventory-close-cancel-",
  );
  const path = join(directory, "empty.zip");
  const bytes = await zipBytes();
  await writeFile(path, bytes);
  const digest = createHash("sha256").update(bytes).digest("hex");
  const output = join(directory, "out");
  const resourceScope = new ArtifactResourceScope();
  const controller = new AbortController();
  const reason = new Error("cancel during inventory reader close");
  const originalReaderClose = ZipArtifactReader.prototype.close;
  let readerCloses = 0;
  const readerClose = vi
    .spyOn(ZipArtifactReader.prototype, "close")
    .mockImplementation(async function (this: ZipArtifactReader) {
      readerCloses += 1;
      await originalReaderClose.call(this);
      if (readerCloses === 1) controller.abort(reason);
    });
  const rootClose = watchZipRootClose(resourceScope, path, (original) =>
    original(),
  );
  try {
    await expect(
      extractArtifact(zipInput(path, output, resourceScope), controller.signal),
    ).rejects.toMatchObject({
      reason: "cancelled",
      cause: reason,
      partialObservation: {
        kind: "artifact-inventory",
        inventory: {
          manifest: { root_format: "zip", root_sha256: digest },
          coverage: { scope: "container-entries", status: "complete" },
        },
      },
    });
    expect(readerCloses).toBe(1);
    expect(rootClose.attempts()).toBe(1);
    expect(resourceScope.hasPending).toBe(false);
    await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    await resourceScope.close();
    rootClose.restore();
    readerClose.mockRestore();
  }
});

it("retains and retries a failed final ZIP descriptor close", async () => {
  const directory = await createTestTempDirectory("rea-zip-extraction-close-");
  const path = join(directory, "empty.zip");
  await writeFile(path, await zipBytes());
  const output = join(directory, "out");
  const resourceScope = new ArtifactResourceScope();
  const failure = new Error("root close denied");
  const rootClose = watchZipRootClose(
    resourceScope,
    path,
    (original, attempt) =>
      attempt === 1 ? Promise.reject(failure) : original(),
  );
  try {
    await expect(
      extractArtifact(zipInput(path, output, resourceScope)),
    ).rejects.toMatchObject({ cleanup: { reason: failure.message } });
    expect(resourceScope.cleanupResources).toEqual([
      `root artifact descriptor for ${path}`,
    ]);
    await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
    await resourceScope.close();
    expect(rootClose.attempts()).toBe(2);
    expect(resourceScope.hasPending).toBe(false);
  } finally {
    await resourceScope.close().catch(() => undefined);
    rootClose.restore();
  }
});

it("retains both failed ZIP inventory owners and retries only those owners", async () => {
  const directory = await createTestTempDirectory("rea-zip-inventory-close-");
  const path = join(directory, "empty.zip");
  await writeFile(path, await zipBytes());
  const resourceScope = new ArtifactResourceScope();
  const originalReaderClose = ZipArtifactReader.prototype.close;
  let readerAttempts = 0;
  const readerClose = vi
    .spyOn(ZipArtifactReader.prototype, "close")
    .mockImplementation(async function (this: ZipArtifactReader) {
      if (++readerAttempts === 1) throw new Error("reader close denied");
      await originalReaderClose.call(this);
    });
  const rootClose = watchZipRootClose(
    resourceScope,
    path,
    (original, attempt) =>
      attempt === 1
        ? Promise.reject(new Error("root close denied"))
        : original(),
  );
  try {
    await expect(
      extractArtifact(zipInput(path, join(directory, "out"), resourceScope)),
    ).rejects.toMatchObject({
      cleanup: {
        resources: [
          `artifact reader for ${path}`,
          `root artifact descriptor for ${path}`,
        ],
      },
    });
    expect(resourceScope.cleanupResources).toEqual([
      `artifact reader for ${path}`,
      `root artifact descriptor for ${path}`,
    ]);
    await resourceScope.close();
    expect(readerAttempts).toBe(2);
    expect(rootClose.attempts()).toBe(2);
  } finally {
    await resourceScope.close().catch(() => undefined);
    rootClose.restore();
    readerClose.mockRestore();
  }
});

it.each([false, true] as const)(
  "retains failed extraction reader cleanup when ZIP root close also fails: %s",
  async (failRootClose) => {
    const directory = await createTestTempDirectory(
      "rea-zip-extraction-mixed-close-",
    );
    const path = join(directory, "empty.zip");
    await writeFile(path, await zipBytes());
    const output = join(directory, "out");
    const resourceScope = new ArtifactResourceScope();
    const originalReaderClose = ZipArtifactReader.prototype.close;
    const readerFailure = new Error("extraction reader close denied");
    const rootFailure = new Error("root close denied");
    let readerAttempts = 0;
    const readerClose = vi
      .spyOn(ZipArtifactReader.prototype, "close")
      .mockImplementation(async function (this: ZipArtifactReader) {
        readerAttempts += 1;
        if (readerAttempts === 2) throw readerFailure;
        await originalReaderClose.call(this);
      });
    const rootClose = watchZipRootClose(
      resourceScope,
      path,
      (original, attempt) =>
        failRootClose && attempt === 1
          ? Promise.reject(rootFailure)
          : original(),
    );
    try {
      await expect(
        extractArtifact(zipInput(path, output, resourceScope)),
      ).rejects.toMatchObject({
        cleanup: {
          resources: failRootClose
            ? [
                `artifact reader for ${path}`,
                `root artifact descriptor for ${path}`,
              ]
            : [`artifact reader for ${path}`],
        },
      });
      expect(resourceScope.cleanupResources).toEqual(
        failRootClose
          ? [
              `artifact reader for ${path}`,
              `root artifact descriptor for ${path}`,
            ]
          : [`artifact reader for ${path}`],
      );
      await expect(stat(output)).rejects.toMatchObject({ code: "ENOENT" });
      await resourceScope.close();
      expect(readerAttempts).toBe(3);
      expect(rootClose.attempts()).toBe(failRootClose ? 2 : 1);
      expect(resourceScope.hasPending).toBe(false);
    } finally {
      await resourceScope.close().catch(() => undefined);
      rootClose.restore();
      readerClose.mockRestore();
    }
  },
);

vi.mock("../pyinstaller/CArchiveLayout.js", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  containsPyInstallerArchive: () =>
    Promise.reject(new ArtifactReaderFailure("format", "detection failed")),
}));

vi.mock("../../filesystem/RegularFile.js", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../../filesystem/RegularFile.js")>();
  return { ...actual, openRegularFile: vi.fn(actual.openRegularFile) };
});

it("keeps the detection error primary and reports a failed detection close", async () => {
  const directory = await createTestTempDirectory("rea-extraction-detect-");
  const path = join(directory, "target.elf");
  await writeFile(path, Buffer.from("not an archive"));
  const resourceScope = new ArtifactResourceScope();
  const originalClose = OwnedFileHandle.prototype.close;
  const closeFailure = new Error("detection close failed");
  let attempts = 0;
  const close = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(async function (this: OwnedFileHandle) {
      attempts += 1;
      if (attempts === 1) throw closeFailure;
      await originalClose.call(this);
    });
  try {
    await expect(
      extractArtifact({
        inputPath: path,
        inputFormat: "elf",
        outputRoot: join(directory, "out"),
        environment: process.env,
        integrityPolicy: "fail",
        resourceScope,
      }),
    ).rejects.toMatchObject({
      reason: "format",
      message: "detection failed",
      cleanup: { reason: closeFailure.message },
    });
    await resourceScope.close();
    expect(attempts).toBe(2);
  } finally {
    close.mockRestore();
    await resourceScope.close().catch(() => undefined);
  }
});

it("plans dry-run extraction with unresolved/unsupported entries and labeled byte estimates without writing to disk", async () => {
  const directory = await createTestTempDirectory("rea-extraction-dry-run-");
  const source = join(directory, "source");
  await mkdir(join(source, "sub"), { recursive: true });
  await writeFile(join(source, "alpha.txt"), "alpha");
  await writeFile(join(source, "sub", "beta.txt"), "beta-bytes");
  await symlink("alpha.txt", join(source, "alias.txt"));
  const dryOutput = join(directory, "dry-out");
  const realOutput = join(directory, "real-out");
  const resourceScope = new ArtifactResourceScope();
  try {
    const planned = await extractArtifact({
      inputPath: source,
      inputFormat: "asar",
      outputRoot: dryOutput,
      dryRun: true,
      environment: {},
      integrityPolicy: "fail",
      resourceScope,
    });
    await expect(stat(dryOutput)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readdir(directory)).toEqual(["source"]);
    expect(planned.dry_run).toBe(true);
    expect(planned.artifacts).toEqual([
      {
        artifact_id: expect.stringMatching(/^art_[a-f0-9]{64}$/u),
        relative_path: "alpha.txt",
        sha256: createHash("sha256").update("alpha").digest("hex"),
        bytes_written: 0,
        created: false,
      },
      {
        artifact_id: expect.stringMatching(/^art_[a-f0-9]{64}$/u),
        relative_path: "sub/beta.txt",
        sha256: createHash("sha256").update("beta-bytes").digest("hex"),
        bytes_written: 0,
        created: false,
      },
    ]);
    expect(planned.plan).toMatchObject({
      entries: [
        {
          logical_path: "alias.txt",
          entry_kind: "symlink",
          status: "unresolved",
          observed_bytes: null,
        },
        {
          logical_path: "alpha.txt",
          entry_kind: "file",
          status: "planned",
          reason: null,
          observed_bytes: 5,
          declared_bytes: 5,
        },
        {
          logical_path: "sub",
          entry_kind: "directory",
          status: "unsupported",
          observed_bytes: null,
        },
        {
          logical_path: "sub/beta.txt",
          entry_kind: "file",
          status: "planned",
          reason: null,
          observed_bytes: 10,
          declared_bytes: 10,
        },
      ],
      totals: {
        planned_files: 2,
        unsupported_entries: 1,
        unresolved_entries: 1,
        observed_bytes_estimate: 15,
        declared_bytes_estimate: 15,
        byte_totals_basis: "declared-and-observed-content-estimates",
      },
    });

    const materialized = await extractArtifact({
      inputPath: source,
      inputFormat: "asar",
      outputRoot: realOutput,
      environment: {},
      integrityPolicy: "fail",
      resourceScope,
    });
    expect(materialized.dry_run).toBeUndefined();
    expect(materialized.plan).toBeUndefined();
    expect(
      planned.artifacts.map(({ artifact_id, relative_path, sha256 }) => ({
        artifact_id,
        relative_path,
        sha256,
      })),
    ).toEqual(
      materialized.artifacts.map(({ artifact_id, relative_path, sha256 }) => ({
        artifact_id,
        relative_path,
        sha256,
      })),
    );
    expect(planned.extraction_manifest.selected_occurrence_ids).toEqual(
      materialized.extraction_manifest.selected_occurrence_ids,
    );
  } finally {
    await resourceScope.close();
  }
});

it("matches real extraction refusal on NFC path collisions and Windows invalid names in dry-run mode", async () => {
  const directory = await createTestTempDirectory(
    "rea-extraction-dry-run-collisions-",
  );
  const collisionZip = join(directory, "collision.zip");
  const writer = new ZipWriter(new Uint8ArrayWriter());
  await writer.add("cafe\u0301.txt", new TextReader("nfd"));
  await writer.add("caf\u00e9.txt", new TextReader("nfc"));
  await writeFile(collisionZip, Buffer.from(await writer.close()));

  const winInvalidZip = join(directory, "win-invalid.zip");
  const winWriter = new ZipWriter(new Uint8ArrayWriter());
  await winWriter.add("stream:data.txt", new TextReader("ads"));
  await writeFile(winInvalidZip, Buffer.from(await winWriter.close()));

  const resourceScope = new ArtifactResourceScope();
  try {
    const dryCollisionOut = join(directory, "dry-collision-out");
    const realCollisionOut = join(directory, "real-collision-out");
    const dryCollisionError = await extractArtifact({
      ...zipInput(collisionZip, dryCollisionOut, resourceScope),
      dryRun: true,
    }).catch((cause: unknown) => cause);
    const realCollisionError = await extractArtifact(
      zipInput(collisionZip, realCollisionOut, resourceScope),
    ).catch((cause: unknown) => cause);
    expect(dryCollisionError).toBeInstanceOf(ArtifactReaderFailure);
    expect(realCollisionError).toBeInstanceOf(ArtifactReaderFailure);
    expect((dryCollisionError as ArtifactReaderFailure).reason).toBe("path");
    expect((dryCollisionError as ArtifactReaderFailure).message).toBe(
      (realCollisionError as ArtifactReaderFailure).message,
    );
    await expect(stat(dryCollisionOut)).rejects.toMatchObject({
      code: "ENOENT",
    });

    const dryWinOut = join(directory, "dry-win-out");
    const realWinOut = join(directory, "real-win-out");
    const dryWinError = await extractArtifact({
      ...zipInput(winInvalidZip, dryWinOut, resourceScope),
      dryRun: true,
      platform: "win32",
    }).catch((cause: unknown) => cause);
    const realWinError = await extractArtifact({
      ...zipInput(winInvalidZip, realWinOut, resourceScope),
      platform: "win32",
    }).catch((cause: unknown) => cause);
    expect(dryWinError).toBeInstanceOf(ArtifactReaderFailure);
    expect(realWinError).toBeInstanceOf(ArtifactReaderFailure);
    expect((dryWinError as ArtifactReaderFailure).reason).toBe("path");
    expect((dryWinError as ArtifactReaderFailure).message).toBe(
      (realWinError as ArtifactReaderFailure).message,
    );
    await expect(stat(dryWinOut)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(stat(realWinOut)).rejects.toMatchObject({ code: "ENOENT" });

    for (const invalidName of [
      "bad?.txt",
      "wild*.txt",
      "angle<left.txt",
      "angle>right.txt",
      'quote"name.txt',
      "pipe|name.txt",
      "trailing-dot./file.txt",
      "trailing-space /file.txt",
      "CON.txt",
      "sub/lpt9",
    ]) {
      const zipPath = join(
        directory,
        `win-${Buffer.from(invalidName).toString("hex")}.zip`,
      );
      const invalidWriter = new ZipWriter(new Uint8ArrayWriter());
      await invalidWriter.add(invalidName, new TextReader("bad"));
      await writeFile(zipPath, Buffer.from(await invalidWriter.close()));
      const invalidDryOut = join(
        directory,
        `out-${Buffer.from(invalidName).toString("hex")}`,
      );
      const err = await extractArtifact({
        ...zipInput(zipPath, invalidDryOut, resourceScope),
        dryRun: true,
        platform: "win32",
      }).catch((cause: unknown) => cause);
      expect(err).toBeInstanceOf(ArtifactReaderFailure);
      expect((err as ArtifactReaderFailure).reason).toBe("path");
      await expect(stat(invalidDryOut)).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
  } finally {
    await resourceScope.close();
  }
});

it("refuses case-folding file and parent directory collisions in dry-run mode when the destination is case-insensitive", async () => {
  const directory = await createTestTempDirectory(
    "rea-extraction-dry-run-case-collision-",
  );
  const fileCaseZip = join(directory, "file-case.zip");
  const fileWriter = new ZipWriter(new Uint8ArrayWriter());
  await fileWriter.add("Foo.txt", new TextReader("upper"));
  await fileWriter.add("foo.txt", new TextReader("lower"));
  await writeFile(fileCaseZip, Buffer.from(await fileWriter.close()));

  const parentCaseZip = join(directory, "parent-case.zip");
  const parentWriter = new ZipWriter(new Uint8ArrayWriter());
  await parentWriter.add("Dir/a.txt", new TextReader("upper-dir"));
  await parentWriter.add("dir/b.txt", new TextReader("lower-dir"));
  await writeFile(parentCaseZip, Buffer.from(await parentWriter.close()));

  const resourceScope = new ArtifactResourceScope();
  try {
    const fileOut = join(directory, "file-case-out");
    const fileError = await extractArtifact({
      ...zipInput(fileCaseZip, fileOut, resourceScope),
      dryRun: true,
      platform: "win32",
    }).catch((cause: unknown) => cause);
    expect(fileError).toBeInstanceOf(DestinationCaseCollisionFailure);
    expect((fileError as DestinationCaseCollisionFailure).reason).toBe("path");
    expect((fileError as DestinationCaseCollisionFailure).message).toBe(
      "Destination filesystem cannot store both foo.txt and Foo.txt; inventory retains both logical names.",
    );
    await expect(stat(fileOut)).rejects.toMatchObject({ code: "ENOENT" });

    const parentOut = join(directory, "parent-case-out");
    const parentError = await extractArtifact({
      ...zipInput(parentCaseZip, parentOut, resourceScope),
      dryRun: true,
      platform: "win32",
    }).catch((cause: unknown) => cause);
    expect(parentError).toBeInstanceOf(DestinationCaseCollisionFailure);
    expect((parentError as DestinationCaseCollisionFailure).reason).toBe(
      "path",
    );
    expect((parentError as DestinationCaseCollisionFailure).message).toBe(
      "Destination filesystem cannot store both dir and Dir; inventory retains both logical names.",
    );
    await expect(stat(parentOut)).rejects.toMatchObject({ code: "ENOENT" });

    const nonAsciiZip = join(directory, "non-ascii-case.zip");
    const nonAsciiWriter = new ZipWriter(new Uint8ArrayWriter());
    await nonAsciiWriter.add("σ.txt", new TextReader("medial"));
    await nonAsciiWriter.add("ς.txt", new TextReader("final"));
    await nonAsciiWriter.add("𐐀.txt", new TextReader("deseret-upper"));
    await nonAsciiWriter.add("𐐨.txt", new TextReader("deseret-lower"));
    await writeFile(nonAsciiZip, Buffer.from(await nonAsciiWriter.close()));
    const nonAsciiOut = join(directory, "non-ascii-case-out");
    const nonAsciiPlan = await extractArtifact({
      ...zipInput(nonAsciiZip, nonAsciiOut, resourceScope),
      dryRun: true,
      platform: "win32",
    });
    expect(nonAsciiPlan.artifacts).toEqual([]);
    expect(nonAsciiPlan.plan?.totals).toMatchObject({
      planned_files: 0,
      unresolved_entries: 4,
      observed_bytes_estimate: 0,
    });
    expect(
      nonAsciiPlan.plan?.entries.map(({ logical_path, status }) => ({
        logical_path,
        status,
      })),
    ).toEqual([
      { logical_path: "ς.txt", status: "unresolved" },
      { logical_path: "σ.txt", status: "unresolved" },
      { logical_path: "𐐀.txt", status: "unresolved" },
      { logical_path: "𐐨.txt", status: "unresolved" },
    ]);
    expect(nonAsciiPlan.limitations).toContain(
      "Non-ASCII case-folding paths depend on the destination filesystem case table and cannot be verified without creating files; affected paths remain unresolved in the dry-run plan.",
    );
    await expect(stat(nonAsciiOut)).rejects.toMatchObject({ code: "ENOENT" });

    if (process.platform !== "win32") {
      const hardlinkParent = join(directory, "hardlink-parent");
      await mkdir(hardlinkParent, { recursive: true });
      await writeFile(join(hardlinkParent, "Foo"), "same-inode");
      await link(join(hardlinkParent, "Foo"), join(hardlinkParent, "foo"));
      const hardlinkOut = join(hardlinkParent, "out");
      const hardlinkPlan = await extractArtifact({
        ...zipInput(fileCaseZip, hardlinkOut, resourceScope),
        dryRun: true,
        platform: "linux",
      });
      expect(hardlinkPlan.plan?.totals).toMatchObject({
        planned_files: 2,
        unresolved_entries: 0,
      });
      expect(
        hardlinkPlan.plan?.entries.map(({ logical_path, status }) => ({
          logical_path,
          status,
        })),
      ).toEqual([
        { logical_path: "Foo.txt", status: "planned" },
        { logical_path: "foo.txt", status: "planned" },
      ]);
      await expect(stat(hardlinkOut)).rejects.toMatchObject({ code: "ENOENT" });
    }

    const emptyMount = join(directory, "empty-mount");
    await mkdir(emptyMount, { recursive: true });
    const unknownOut = join(emptyMount, "out");
    const unknownPlan = await extractArtifact({
      ...zipInput(fileCaseZip, unknownOut, resourceScope),
      dryRun: true,
      platform: "linux",
    });
    expect(unknownPlan.artifacts).toEqual([]);
    expect(unknownPlan.plan?.totals).toMatchObject({
      planned_files: 0,
      unresolved_entries: 2,
      observed_bytes_estimate: 0,
    });
    expect(
      unknownPlan.plan?.entries.map(({ logical_path, status }) => ({
        logical_path,
        status,
      })),
    ).toEqual([
      { logical_path: "Foo.txt", status: "unresolved" },
      { logical_path: "foo.txt", status: "unresolved" },
    ]);
    expect(unknownPlan.limitations).toContain(
      "Destination directory case sensitivity is unknown because the destination parent has no observable cased entry; case-colliding paths remain unresolved in the dry-run plan.",
    );
    await expect(stat(unknownOut)).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    await resourceScope.close();
  }
});

it("observes cancellation that arrives while closing a non-ZIP reader in dry-run mode", async () => {
  const directory = await createTestTempDirectory(
    "rea-extraction-dry-run-cancel-close-",
  );
  const source = join(directory, "source");
  await mkdir(source, { recursive: true });
  await writeFile(join(source, "alpha.txt"), "alpha");
  const controller = new AbortController();
  const reason = new Error("cancel during directory reader close");
  const originalClose = DirectoryArtifactReader.prototype.close;
  let extractionCleanupCall = false;
  const closeSpy = vi
    .spyOn(DirectoryArtifactReader.prototype, "close")
    .mockImplementation(async function (this: DirectoryArtifactReader) {
      if (extractionCleanupCall) controller.abort(reason);
      extractionCleanupCall = true;
      await originalClose.call(this);
    });
  const resourceScope = new ArtifactResourceScope();
  try {
    await expect(
      extractArtifact(
        {
          inputPath: source,
          inputFormat: "asar",
          outputRoot: join(directory, "dry-out"),
          dryRun: true,
          environment: {},
          integrityPolicy: "fail",
          resourceScope,
        },
        controller.signal,
      ),
    ).rejects.toMatchObject({
      reason: "cancelled",
      cause: reason,
    });
  } finally {
    closeSpy.mockRestore();
    await resourceScope.close();
  }
});

it("retains observed_bytes on unsupported nested ASAR members without adding them to planned byte totals", async () => {
  const directory = await createTestTempDirectory(
    "rea-extraction-dry-run-nested-asar-",
  );
  const source = join(directory, "application");
  await mkdir(join(source, "resources"), { recursive: true });
  const nestedPayload = Buffer.from("nested-main-payload");
  const nestedAsar = Buffer.concat([
    asarHeaderBytes(
      JSON.stringify({
        files: {
          "main.js": {
            size: nestedPayload.byteLength,
            offset: "0",
          },
        },
      }),
    ),
    nestedPayload,
  ]);
  await writeFile(join(source, "resources", "app.asar"), nestedAsar);
  const resourceScope = new ArtifactResourceScope();
  try {
    const planned = await extractArtifact({
      inputPath: source,
      inputFormat: "asar",
      outputRoot: join(directory, "dry-out"),
      dryRun: true,
      environment: {},
      integrityPolicy: "fail",
      resourceScope,
    });
    expect(planned.plan).toBeDefined();
    const containerEntry = planned.plan?.entries.find(
      ({ logical_path }) => logical_path === "resources/app.asar",
    );
    const nestedMemberEntry = planned.plan?.entries.find(
      ({ logical_path }) => logical_path === "resources/app.asar/main.js",
    );
    expect(containerEntry).toMatchObject({
      logical_path: "resources/app.asar",
      entry_kind: "file",
      status: "planned",
      observed_bytes: nestedAsar.byteLength,
      declared_bytes: nestedAsar.byteLength,
    });
    expect(nestedMemberEntry).toMatchObject({
      logical_path: "resources/app.asar/main.js",
      entry_kind: "file",
      status: "unsupported",
      observed_bytes: nestedPayload.byteLength,
      declared_bytes: nestedPayload.byteLength,
    });
    expect(planned.plan?.totals).toMatchObject({
      planned_files: 1,
      unsupported_entries: 2,
      unresolved_entries: 0,
      observed_bytes_estimate: nestedAsar.byteLength,
      declared_bytes_estimate: nestedAsar.byteLength,
    });
  } finally {
    await resourceScope.close();
  }
});

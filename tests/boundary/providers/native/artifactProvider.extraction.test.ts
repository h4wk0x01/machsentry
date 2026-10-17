import { access, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createHash } from "node:crypto";

import { describe, expect, it, onTestFinished } from "vitest";

import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

import { ArtifactProvider } from "../../../../src/artifacts/ArtifactProvider.js";
import { artifactExtractionExecutionSchema } from "../../../../src/contracts/artifactToolContracts.js";
import {
  artifactExtractionResultSchema,
  artifactInventoryResultSchema,
} from "../../../../src/domain/artifactGraph.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import {
  CPU,
  fatImage,
  machoImage,
} from "../../../../src/artifacts/apple/MachoImage.fixture.js";
import { parseBinaryTarget } from "../../../../src/application/BinaryTargetResolver.js";

describe("structural Mach-O extraction", () => {
  it.skipIf(process.platform === "darwin")(
    "extracts universal Mach-O slices with inventory digests and source ranges without lipo",
    async () => {
      const root = await createTestTempDirectory("rea-extract-fat-structural-");
      const source = join(root, "universal");
      const slices = [
        {
          cpu: CPU.x86_64,
          bytes: machoImage({ cpu: CPU.x86_64 }),
          name: "x86_64",
        },
        {
          cpu: CPU.arm64,
          bytes: machoImage({ cpu: CPU.arm64 }),
          name: "arm64",
        },
      ];
      const original = Buffer.from(fatImage(slices));
      await writeFile(source, original);
      const parsed = await parseBinaryTarget(source);
      if (!parsed.ok) throw parsed.error;
      const client = new ArtifactProvider(process.env).createClient(
        parsed.value,
      );
      onTestFinished(async () => {
        const closed = await client.close();
        if (!closed.ok) throw closed.error;
      });
      const inspected = await client.execute("inventory_artifact", {});
      if (!inspected.ok) throw inspected.error;
      const graph = artifactInventoryResultSchema.parse(inspected.value.result);
      const extracted = await client.execute("extract_artifact", {
        output_root: join(root, "output"),
      });
      if (!extracted.ok) throw extracted.error;
      const result = artifactExtractionResultSchema.parse(
        extracted.value.result,
      );
      expect(result.containment_verified).toBe(true);
      expect(result.provenance).toEqual([]);
      expect(result.artifacts).toHaveLength(2);
      for (const [index, slice] of slices.entries()) {
        const path = `slices/${slice.name}`;
        const expectedHash = createHash("sha256")
          .update(slice.bytes)
          .digest("hex");
        const occurrence = graph.occurrences.find(
          ({ logical_path }) => logical_path === path,
        );
        expect(occurrence).toMatchObject({
          entry_kind: "slice",
          source_location: {
            offset: (index + 1) * 4096,
            length: slice.bytes.length,
          },
        });
        expect(
          result.artifacts.find(({ relative_path }) => relative_path === path),
        ).toMatchObject({
          artifact_id: occurrence?.artifact_id,
          sha256: expectedHash,
        });
        expect(await readFile(join(result.output_root, path))).toEqual(
          Buffer.from(slice.bytes),
        );
      }
      expect(await readFile(source)).toEqual(original);
    },
  );
});

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

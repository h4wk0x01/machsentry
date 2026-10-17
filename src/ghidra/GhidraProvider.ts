import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { bindArtifactFileCleanup } from "../artifacts/ArtifactFileOperation.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import type {
  AnalysisClient,
  AnalysisClientContext,
  AnalysisProfileResolutionOptions,
  AnalysisProfileResolution,
  AnalysisProviderCandidate,
  AnalysisProviderReadinessSnapshot,
  CapabilityDescriptor,
  ProviderAvailability,
  ProviderIdentity,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import type { AppConfig } from "../config/types.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import {
  isMachOFormat,
  type BinaryTarget,
} from "../domain/binaryTargetTypes.js";
import {
  jsonObjectSchema,
  jsonValueSchema,
  type JsonValue,
} from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { Logger } from "pino";
import { GhidraClient } from "./GhidraClient.js";
import {
  ghidraInstallationDiagnostics,
  inspectGhidraInstallation,
  type GhidraInstallationHost,
  type GhidraInstallationInspection,
} from "./GhidraInstallation.js";
import { resolveGhidraAnalysisProfile } from "./GhidraAnalysisProfile.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { resolveGhidraAnalysisSeeds } from "./GhidraAnalysisSeeds.js";
import {
  admitGhidraLanguageOverride,
  GhidraLanguageCatalogCleanupError,
  readGhidraLanguageCatalog,
} from "./GhidraLanguageCatalog.js";
import {
  ghidraProcessorUnsupportedReason,
  isGhidraPspTarget,
} from "./GhidraPspProfile.js";
import { resolveGhidraExtensions } from "./extensions/GhidraExtensions.js";
import {
  CAPABILITIES,
  windowsP0Capabilities,
  GHIDRA_PROVIDER_IDENTITY,
  WINDOWS_P0_NATIVE_PE_ARCHITECTURES,
  WINDOWS_P0_MACH_O_ARCHITECTURES,
} from "./GhidraProviderCapabilities.js";
import {
  createGhidraProviderClient,
  type GhidraProviderClientFactory,
} from "./GhidraProviderClient.js";
import {
  inspectWindowsNativeReadiness,
  type WindowsNativeReadiness,
  windowsNativeCapabilities,
} from "../process/WindowsAuthority.js";

const SUPPORTED_ARCHITECTURES = new Set([
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "mips",
  "6502",
  "riscv",
  "powerpc",
  "m68k",
]);

/** Ghidra candidate backed by an isolated ephemeral headless import. */
export class GhidraProvider implements AnalysisProviderCandidate {
  readonly #inspectionResources = new ArtifactResourceScope();
  readonly #profileWork = new Set<
    Promise<Result<AnalysisProfileResolution, AnalysisError>>
  >();
  #closing: Promise<Result<null, AnalysisError>> | undefined;
  #installation: GhidraInstallationInspection | undefined;
  private readonly environment: NodeJS.ProcessEnv;

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    environment: Readonly<NodeJS.ProcessEnv>,
    private readonly installationHost?: GhidraInstallationHost,
    private readonly clientFactory: GhidraProviderClientFactory = (options) =>
      new GhidraClient(options),
  ) {
    this.environment = snapshotEnvironment(
      environment,
      installationHost?.platform,
    );
  }

  identity(): ProviderIdentity {
    return GHIDRA_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return (this.installationHost?.platform ?? process.platform) === "win32"
      ? windowsP0Capabilities()
      : CAPABILITIES;
  }

  inspectAvailability(): ProviderAvailability {
    return this.inspectReadinessSnapshot().availability;
  }

  inspectReadinessSnapshot(): AnalysisProviderReadinessSnapshot {
    const installation = this.#inspectInstallation();
    const readiness =
      installation.platform === "win32"
        ? inspectWindowsNativeReadiness(installation.platform)
        : undefined;
    return {
      availability: this.#availability(installation, readiness),
      capabilities:
        readiness === undefined
          ? CAPABILITIES
          : windowsP0Capabilities(readiness),
    };
  }

  #availability(
    installation: GhidraInstallationInspection,
    readiness: WindowsNativeReadiness | undefined,
  ): ProviderAvailability {
    const diagnostics = ghidraInstallationDiagnostics(installation);
    if (installation.status === "available" && readiness?.available === false)
      return {
        status: "unavailable",
        code: readiness.code,
        reason: readiness.reason,
        diagnostics: {
          ...diagnostics,
          windows_security: jsonObjectSchema.parse(
            windowsNativeCapabilities(installation.platform, readiness),
          ),
          windows_native_failure: {
            stage: readiness.failureStage,
            remediation: readiness.remediation,
          },
        },
      };
    return installation.status === "available"
      ? {
          status: "available",
          code: null,
          reason: null,
          diagnostics,
        }
      : {
          status: "unavailable",
          code: installation.rejection.code,
          reason: installation.rejection.reason,
          diagnostics,
        };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const hostPlatform = this.installationHost?.platform ?? process.platform;
    const diagnostics = {
      host_platform: hostPlatform,
      target_kind: target.kind,
      target_format: target.format,
      architecture: target.architecture ?? null,
      available_architectures:
        target.kind === "executable"
          ? [...target.availableArchitectures]
          : null,
      executable_role: target.executableRole ?? null,
      managed: target.managed ?? null,
    };
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason: `Ghidra v1 imports executable targets, not ${target.kind} targets.`,
        diagnostics,
      };
    if (hostPlatform === "win32")
      return inspectWindowsP0TargetSupport(target, diagnostics);
    const mipsReason =
      isGhidraPspTarget(target) &&
      (hostPlatform !== "linux" ||
        (this.installationHost?.architecture ?? process.arch) !== "x64")
        ? "The initial PSP Allegrex profile is verified on Linux x64 only."
        : ghidraProcessorUnsupportedReason(target);
    if (mipsReason !== null)
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: mipsReason,
        diagnostics,
      };
    if (
      isMachOFormat(target.format) &&
      target.availableArchitectures.length > 1
    )
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Ghidra v1 cannot enforce the selected architecture when importing a universal Mach-O; analyze a thinned Mach-O slice instead.",
        diagnostics,
      };
    if (!SUPPORTED_ARCHITECTURES.has(target.architecture))
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Ghidra v1 requires a supported x86, x86_64, arm, arm64, MIPS, RISC-V, raw 6502, or raw m68k target profile.",
        diagnostics,
      };
    return {
      status: "supported",
      code: null,
      reason: null,
      diagnostics,
    };
  }

  hasPendingOwnedResources(): boolean {
    return this.#profileWork.size > 0 || this.#inspectionResources.hasPending;
  }

  closeOwnedResources() {
    this.#closing ??= Promise.resolve()
      .then(async () => {
        await Promise.allSettled(this.#profileWork);
        return this.#closeInspectionResources();
      })
      .finally(() => {
        this.#closing = undefined;
      });
    return this.#closing;
  }

  async #closeInspectionResources() {
    try {
      await this.#inspectionResources.retryCleanup();
      return ok(null);
    } catch (cause: unknown) {
      const error = new ProviderCleanupError(
        "ghidra",
        cause instanceof ArtifactReaderFailure
          ? (cause.cleanup?.resources ?? [])
          : [],
        { reason: providerFailureText(cause) },
        { cause },
      );
      bindArtifactFileCleanup(cause, error);
      return err(error);
    }
  }

  async resolveAnalysisProfile(
    target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ): Promise<Result<AnalysisProfileResolution, AnalysisError>> {
    if (this.#closing !== undefined) {
      const closed = await this.#closing;
      if (!closed.ok) return closed;
    }
    const work = Promise.resolve().then(() =>
      this.#resolveProfile(target, options),
    );
    this.#profileWork.add(work);
    try {
      return await work;
    } finally {
      this.#profileWork.delete(work);
    }
  }

  async #resolveProfile(
    target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ) {
    const installation = this.#inspectInstallation();
    const resolved = await resolveGhidraAnalysisProfile(
      target,
      GHIDRA_PROVIDER_IDENTITY,
      installation,
      this.#inspectionResources,
      options?.signal,
      this.config.ghidraLanguageOverride,
      this.config.ghidraDisabledAnalyzers,
    );
    if (!resolved.ok || resolved.value.profile === null) return resolved;
    const override = this.config.ghidraLanguageOverride;
    if (override !== undefined && installation.status === "available") {
      let catalog: Awaited<ReturnType<typeof readGhidraLanguageCatalog>>;
      try {
        catalog = await readGhidraLanguageCatalog(installation.installDir);
      } catch (cause: unknown) {
        if (cause instanceof GhidraLanguageCatalogCleanupError)
          return err(
            new ProviderCleanupError(
              "ghidra",
              cause.paths,
              {
                reason: cause.message,
                paths: [...cause.paths],
                close_failures: cause.causes.map(providerFailureText),
                ...(cause.readFailure === undefined
                  ? {}
                  : { read_failure: providerFailureText(cause.readFailure) }),
              },
              { operation: "resolve_analysis_profile", cause },
            ),
          );
        return err(
          new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
            cause,
            diagnostics: {
              reason:
                "Could not read the installed Ghidra language definitions.",
            },
          }),
        );
      }
      const refused = admitGhidraLanguageOverride(
        override,
        catalog,
        installation.providerVersion,
      );
      if (refused !== null) return err(refused);
    }
    const extensions = await resolveGhidraExtensions(
      this.config,
      target,
      installation.platform,
      this.#inspectionResources,
      options?.signal,
    );
    if (!extensions.ok) return extensions;
    if (options?.signal?.aborted === true)
      return err(
        new AnalysisCancelledError("open_binary", {
          cause: options.signal.reason,
        }),
      );
    const seeds = await resolveGhidraAnalysisSeeds(
      this.config.ghidraSeedFile,
      this.#inspectionResources,
      options?.signal,
    );
    if (!seeds.ok) return seeds;
    if (extensions.value.length === 0 && seeds.value === undefined)
      return resolved;
    return ok({
      ...resolved.value,
      profile: createAnalysisProfile(resolved.value.profile.provider, {
        ...resolved.value.profile.parameters,
        ...(extensions.value.length === 0
          ? {}
          : { analysis_extensions: jsonValueSchema.parse(extensions.value) }),
        ...(seeds.value === undefined
          ? {}
          : { analysis_seeds: jsonValueSchema.parse(seeds.value) }),
      }),
    });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
    context?: AnalysisClientContext,
  ): AnalysisClient {
    return createGhidraProviderClient({
      config: this.config,
      environment: this.environment,
      logger: this.logger,
      clientFactory: this.clientFactory,
      target,
      ...(profile === undefined ? {} : { profile }),
      ...(context === undefined ? {} : { context }),
      installation: this.#inspectInstallation(),
    });
  }

  #inspectInstallation(): GhidraInstallationInspection {
    const options = {
      environment: this.environment,
      ...(this.config.ghidraInstallDir === undefined
        ? {}
        : { installDir: this.config.ghidraInstallDir }),
      ...(this.config.ghidraJavaHome === undefined
        ? {}
        : { javaHome: this.config.ghidraJavaHome }),
      ...(this.installationHost?.platform === undefined
        ? {}
        : { platform: this.installationHost.platform }),
      ...(this.installationHost?.architecture === undefined
        ? {}
        : { architecture: this.installationHost.architecture }),
    };
    this.#installation ??=
      this.installationHost === undefined
        ? inspectGhidraInstallation(options)
        : inspectGhidraInstallation(options, this.installationHost);
    return this.#installation;
  }
}

const providerFailureText = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const inspectWindowsP0TargetSupport = (
  target: BinaryTarget,
  diagnostics: Readonly<Record<string, JsonValue>>,
): ProviderTargetSupport => {
  if (isMachOFormat(target.format)) {
    if (target.format === "mach-o-universal")
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Windows Ghidra imports thin Mach-O slices only. Use extract_artifact to retain each universal slice's source range and digest, then open the selected extracted slice.",
        diagnostics,
      };
    if (
      target.architecture === undefined ||
      !WINDOWS_P0_MACH_O_ARCHITECTURES.includes(target.architecture)
    )
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Windows Ghidra admits thin x86-64 and ARM64 Mach-O targets only.",
        diagnostics,
      };
    return { status: "supported", code: null, reason: null, diagnostics };
  }
  // The raw 6502 lane uses the same immutable snapshot and native ownership boundary.
  if (target.format === "raw-binary" && target.architecture === "6502")
    return { status: "supported", code: null, reason: null, diagnostics };
  if (target.format !== "pe")
    return {
      status: "unsupported",
      code: "target_format_unsupported",
      reason:
        "Windows Ghidra P0 accepts native PE, thin x86-64/ARM64 Mach-O, and explicitly selected raw 6502 targets only.",
      diagnostics,
    };
  if (!WINDOWS_P0_NATIVE_PE_ARCHITECTURES.includes(target.architecture))
    return {
      status: "unsupported",
      code: "architecture_unsupported",
      reason:
        "Windows Ghidra P0 accepts x86, x86-64, ARM and ARM64 PE targets only.",
      diagnostics,
    };
  if (
    target.executableRole !== "application" &&
    target.executableRole !== "shared-library"
  )
    return {
      status: "unsupported",
      code: "target_role_unsupported",
      reason:
        "Windows Ghidra P0 accepts PE applications and DLLs, not non-executable or unclassified images.",
      diagnostics,
    };
  if (target.managed !== false)
    return {
      status: "unsupported",
      code: "managed_target_unsupported",
      reason:
        "Windows Ghidra P0 accepts native PE applications and DLLs; managed or unclassified PE targets are unsupported.",
      diagnostics,
    };
  if (
    (target.architecture === "arm" && target.peMachine !== 0x01c4) ||
    (target.architecture === "arm64" && target.peMachine !== 0xaa64)
  )
    return {
      status: "unsupported",
      code: "architecture_unsupported",
      reason:
        "Windows Ghidra P0 ARM PE targets require observed ARMNT (0x01c4) or ARM64 (0xaa64) COFF machines; legacy ARM/Thumb and unknown machines are unsupported.",
      diagnostics: { ...diagnostics, pe_machine: target.peMachine ?? null },
    };
  return {
    status: "supported",
    code: null,
    reason: null,
    diagnostics,
  };
};

# ADR 0004: Three-Step Cross-Platform Web App Deployment

Status: Accepted for P0 baseline
Date: 2026-08-31

## Context

The same Web application must be usable on Mac, Linux, and Windows without
shipping three native products. A new-machine user must reach the diagnosis
home page in three visible steps. Hidden edits, migrations, token discovery, or
extra operator commands would violate the approved usability requirement.

Docker documents Docker Desktop with Compose for Linux, Mac, and Windows. The
Compose build specification supports `linux/amd64` and `linux/arm64` target
platforms. Docker Desktop GPU support on Windows is limited to its WSL2 backend
with a compatible NVIDIA GPU and drivers. These are platform prerequisites, not
evidence that this product has passed qualification.

Sources:

- <https://docs.docker.com/compose/install/>
- <https://docs.docker.com/reference/compose-file/build/#platforms>
- <https://docs.docker.com/desktop/features/gpu/>

## Decision

P0 is a browser Web App backed by the same Linux container images on each host.
External-model mode targets Mac, Linux, and Windows. Release images publish an
OCI manifest for `linux/amd64` and `linux/arm64`.

The customer journey has exactly three user steps:

1. Install the container runtime: Docker Desktop on Mac/Windows, or Docker
   Engine plus the Compose plugin on Linux.
2. Download the matching release archive and double-click its launcher or run
   one command. The launcher detects architecture, verifies artifact signatures
   and checksums, checks port/disk/runtime prerequisites, runs safe migrations,
   starts services, and prints the local URL and one-time initialization code.
3. Open the Web URL, enter the code, select external inference or an already
   verified local runtime, commit policy/connectors, and pass the built-in
   self-test before entering the diagnosis home page.

The release may contain small platform-specific launchers, but it is one
versioned product release and one Compose/model-mode contract. A launcher must
not silently relax security controls or download a different product variant.

No supported happy path requires editing `.env`, editing Compose, selecting an
override, locating a token file, running a migration command, or issuing a
second product command. A failed preflight stays within step 2 and prints a
specific remediation. A failed setup check stays within step 3 and is resumable.

The default bind address is loopback. LAN/remote access is a separate explicit
configuration that requires TLS, authentication, and an exposure warning.

## Platform Qualification

- macOS Intel and Apple Silicon: external-model path is a P0 target. Apple GPU
  local inference is not included in the NVIDIA-container P0 claim.
- Linux amd64/arm64: external-model path is a P0 target. Linux with qualified
  NVIDIA hardware/toolkit is the first local-GPU qualification target.
- Windows 10/11: external-model path through Docker Desktop/WSL2 is a P0 target.
  Local GPU remains unverified until the exact Windows/WSL2/NVIDIA/model/runtime
  combination passes the same qualification suite.

Only a platform with clean-install evidence is shown as verified. Unsupported
or unavailable local hardware degrades to external-model or deterministic-rule
mode without blocking Web App deployment.

## Release Evidence

For each platform, QA records the machine/OS/architecture/runtime versions,
exact three steps, elapsed time, artifact digest, output URL/bootstrap behavior,
path/volume/port handling, restart, upgrade, uninstall, data retention, and
failure remediation. Screenshots do not replace commands, logs, and outcomes.

## Consequences

- Multi-architecture build, signing/provenance/SBOM, launchers, and three real
  host environments become release dependencies.
- A generic `docker compose up` remains a developer path; the customer launcher
  owns preflight, migration, and human-readable error handling.
- No platform or local-GPU combination is marketed before real qualification.

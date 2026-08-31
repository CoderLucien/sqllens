# ADR 0001: One Package With Two Model Modes

Status: Accepted for P0 baseline
Date: 2026-08-31

## Context

The product must ship as one delivery package. After Docker starts, the user
selects either an external model or private local inference in the Web setup
wizard. The application must not receive Docker Socket or equivalent host-root
control. Low mode must be capable of running under a total 2 CPU / 4 GiB budget.

A Web application cannot safely create a stopped Compose-profile service or
expose a previously hidden GPU without a host control plane. Treating that as a
Web-only action would make the deployment contract impossible or require an
unacceptable Docker Socket mount.

## Decision

The release artifact contains one versioned manifest set:

- a base Compose definition for the application, worker, and an idle internal
  model controller;
- a GPU override from the same release for hosts that expose an accelerator;
- one Web setup wizard and one provider gateway for both modes.

Host provisioning occurs before containers start. The installer or operator
selects the GPU override when appropriate. Web setup owns product configuration,
model probing, artifact selection, and activation only after the device is
already visible.

The application never mounts Docker Socket. The model controller has no host
filesystem access, exposes no host port, accepts authenticated calls only on an
internal network, and owns the inference subprocess. Low mode downloads no
weights and includes the idle controller in the 2C4G benchmark.

Model configuration is revisioned. Every diagnosis job pins provider, model,
runtime artifact, prompt, redaction, and policy revisions. Mode switching drains
or cancels affected jobs before atomically activating the new revision.

## Consequences

- One package and Web selection remain true without granting host-root power.
- Switching from external to local on a host started without GPU exposure
  requires an operator restart with the same-package GPU override.
- The controller idle footprint is part of the low-mode acceptance test.
- Local-mode claims require an exact model/runtime artifact and real hardware
  qualification; simulated probes are reported as unverified.

## Rejected Alternatives

- Mount Docker Socket into the application: equivalent to broad host control.
- Start a Compose profile from Web: impossible without a host control plane.
- Put the 30B model in the application process: couples OOM and crash domains
  and makes the 2C4G image/path impractical.
- Ship two product packages: conflicts with the approved delivery experience.

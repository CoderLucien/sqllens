# QA Environment Baseline

Captured: 2026-08-31 23:45 CST
Purpose: capability classification only; not a performance result

## Current Linux Workspace Host

| Property | Observed |
|---|---|
| Operating system | Ubuntu 24.04 LTS (Noble Numbat) |
| Architecture | Linux x86_64 |
| Logical CPU | 4 |
| Physical memory | 3.6 GiB total, about 1.4 GiB available at capture |
| Swap | 1.9 GiB total, about 1.3 GiB used at capture |
| Root filesystem | 40 GiB total, 7.6 GiB free, 80% used at capture |
| Docker Engine | 29.1.3 |
| Docker Compose | 2.40.3 (Ubuntu package) |

Commands:

```bash
cat /etc/os-release
uname -m
docker version --format '{{.Server.Version}}'
docker compose version
nproc
free -h
df -h /root
```

## Permitted Claims

This host can run Ubuntu 24.04 functional smoke tests, deterministic
fake-provider tests, bounded hostile-input tests, and preliminary
container-limit harness checks once release images exist. Results from this
host do not qualify CentOS or any other Linux distribution.

It cannot by itself qualify:

- the 2C4G performance target: available host memory is below 4 GiB, swap and
  unrelated host activity would confound RSS, latency and OOM/fuse behavior;
- Mac or Windows clean installation;
- CentOS clean installation or runtime compatibility;
- native `linux/arm64` execution;
- real TiDB/Prometheus compatibility or incremental-impact A/B without a
  separately provisioned disposable topology;
- local-model GPU behavior because no target GPU/artifact is recorded here.

At least one dedicated Linux benchmark host with headroom beyond the enforced
container budget is required. Mac, Windows, arm64, TiDB/Prometheus and GPU
evidence remain separate E2/E4/E5 requirements in the QA matrix.

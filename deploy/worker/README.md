# MachSentry worker on AWS (Unpacked analysis pilot)

This directory and `deploy/aws/worker.yaml` put MachSentry (REA MCP and Ghidra)
on an on-demand EC2 worker for the private Mach-O analysis pilot of Unpacked.
The specification is `docs/ANALYSIS-SERVICE-CONTRACT.md` in the Unpacked
repository, sections 1 (AWS resources) and 9 (worker host).

| File                                                                    | Role                                                                                                                  |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `deploy/aws/worker.yaml`                                                | CloudFormation stack `unpacked-analysis`: bucket, site and worker roles, worker instance, idle alarm, optional budget |
| `scripts/deploy_machsentry_aws.py`                                      | Operator CLI for AWS CloudShell; every change is printed first, `--dry-run` stops there                               |
| `deploy/worker/bootstrap.sh`                                            | Runs on the worker through SSM: packages, Docker, analyzer image, verification, units                                 |
| `deploy/worker/Dockerfile`                                              | Analyzer image `machsentry-analyzer:<commit>`, built on the worker from a release archive                             |
| `deploy/worker/systemd/`                                                | `machsentry-supervisor.service`, `machsentry-watchdog.service` and `.timer`                                           |
| `deploy/worker/maintenance-gate.py`                                     | Supervisor `ExecCondition`: skips a boot while the deploy script holds the instance                                   |
| `deploy/worker/docker-daemon.json`, `journald.conf`, `needrestart.conf` | Host configuration installed by the bootstrap                                                                         |

The worker has no SSH key and no inbound rule. Administration goes through SSM
Run Command. Samples reach it only through presigned URLs that the site grants
per job, and each analysis runs in a new container with `--network none`.

## Before you start

- Open AWS CloudShell in `us-east-2`, signed in to account `835176962667`. The
  script checks the account on every command and refuses any other.
- The MachSentry commit to install must be on GitHub (or pass `--repo` with a
  clone that has it). It must contain `worker/` with `requirements.lock.txt`.
- The Unpacked site with the analysis API must already be deployed, with
  `ANALYSIS_SERVICE` still unset, so the demo stays on until the worker passes.

```bash
git clone https://github.com/h4wk0x01/machsentry
cd machsentry
alias worker='python3 scripts/deploy_machsentry_aws.py'
```

## First install

1. `worker preflight` checks the account, picks the default VPC and a public
   subnet whose zone offers `t3a.medium`, resolves the Canonical Ubuntu 24.04
   AMI, reports the stack, the site instance profile, which SSM parameters exist
   (names only) and prints the monthly cost estimate.
2. `worker plan` creates a CloudFormation change set, prints it and discards it.
3. `worker deploy --yes --budget-email you@example.com` creates the stack. Leave
   out `--budget-email` if the account already has a cost budget. It also creates
   the `AWSServiceRoleForCloudWatchEvents` service-linked role that the alarm's
   stop action needs. The new instance starts running; the bootstrap below stops
   it, and the idle alarm stops it after 15 minutes otherwise.
4. `worker put-worker-token` creates `/unpacked/analysis/worker/token`
   (SecureString, 32 random bytes) and prints only its SHA-256.
5. In the Systems Manager console, create `/unpacked/analysis/openai/api-key` as
   a SecureString with the AI key. The script never reads or writes it.
6. `worker site-params` writes `site-url`, `mode=active` (only when absent) and
   `openai/model`.
7. `worker associate-site-profile` gives the site instance `i-07c2e746122fe1b94`
   the `unpacked-site-analysis` profile. It refuses when the instance already
   has a different profile; merge the statements into that role in that case.
8. `worker release --commit <sha>` uploads `git archive` of the commit to
   `s3://unpacked-analysis-835176962667-us-east-2/releases/` and records commit,
   key and SHA-256 in `/unpacked/analysis/worker/release`. Archives that contain
   anything under `amostras/`, `reports/` or local runtimes are refused.
9. `worker bootstrap --unlimited-during-build` starts the worker, waits for SSM,
   sends the release through a one-hour presigned URL, checks its SHA-256 and runs
   `bootstrap.sh`. The first build downloads Ghidra, the JDK and Node, builds REA
   and takes roughly 20 to 40 minutes. The flag keeps the build from running out
   of CPU credits and puts the instance back on standard credits afterwards.
   The worker is stopped at the end; `--keep-running-on-failure` leaves it on
   for inspection when something fails.
   CloudShell ends a session after 20 to 30 minutes without keyboard input,
   and a first build takes longer. The SSM command keeps running on the worker
   when the session ends. The next `worker status`, `release`, `bootstrap` or
   `rollback` waits until that command has ended, then puts the instance back on
   standard credits and removes the maintenance tag, which the site and the
   supervisor honor. The idle alarm stops the instance in the meantime.
10. `worker site-env` prints the lines for `/srv/unpacked/shared/env`
    (`ANALYSIS_SERVICE=aws`, region, bucket, worker instance id and the token
    hash). Add them with `./scripts/deploy.sh --env` in the Unpacked checkout,
    add `ANALYSIS_RECONCILE_TOKEN` generated on the site, and redeploy the site:
    the bucket host enters the CSP at build time.

## What the bootstrap does on the worker

All steps are idempotent, and a failed step leaves the previous release active.

Before it changes anything, starting a stopped worker included, the deploy
script tags the instance `unpacked-analysis:maintenance` (with the time, and the
SSM command once sent).
The site neither starts nor stops the worker while the tag is on, and the
supervisor unit reads it through IMDS (`InstanceMetadataTags: enabled` in the
template): `maintenance-gate.py` skips the boot while the tag is less than an
hour old, so the previous release claims no job before the bootstrap arrives.
The SSM wrapper only downloads, checks and unpacks the release under the
bootstrap lock; it stops nothing.

1. Refuses to continue while a job is in progress: a container with the
   supervisor's `machsentry.job` label, or, while the supervisor runs, the
   attempt that `state.json` records (the AI review and the publishing happen
   after the container is gone). `--force` overrides, and that attempt ends as
   `worker_lost`. A refusal stops nothing, and the deploy script leaves the
   instance on for the supervisor. Otherwise it creates
   `/run/machsentry-worker-maintenance` and stops the supervisor and the
   watchdog. `/run` is a tmpfs: if the instance stops in the middle, the
   previous release starts at the next boot.
2. Installs `docker.io 29.1.3-0ubuntu3~24.04.2` and `docker-buildx
   0.30.1-0ubuntu1~24.04.1` (noble-updates on 2026-10-18, then held), plus
   procps, python3-venv, e2fsprogs, jq, ca-certificates and apparmor.
3. Writes `daemon.json` (json-file logs of 10 MB x 2, `no-new-privileges`, no
   inter-container traffic, no userland proxy, no live restore), keeps journald
   for 7 days within 200 MB, tells needrestart to leave Docker alone and
   installs `maintenance-gate.py` in `/opt/machsentry-worker/bin`.
4. Installs the supervisor venv in `/opt/machsentry-worker/venvs/<commit>` from
   `worker/requirements.lock.txt` with `--require-hashes`. It builds the venv
   aside, from a copy of `worker/` (the release stays a plain git archive), and
   renames it into place only when it is complete, so the active venv survives
   a failed download.
5. Builds `machsentry-analyzer:<commit>` (base `ubuntu:24.04` pinned by digest).
   The image sets `JAVA_HOME`, `GHIDRA_INSTALL_DIR` and a `PATH` where `python`
   is the MachSentry venv and `node` the pinned Node; the build fails if they
   differ from the `.tools/runtime.json` that setup wrote.
6. Runs, with the same isolation as a job and a 4 GiB loop-mounted work
   directory, `node scripts/rea.mjs doctor --provider ghidra --json` and then
   `scripts/verify-machsentry-ghidra.py`: real Ghidra decompilation of inert
   synthetic Mach-O fixtures and a full MachSentry report with YARA checks. It
   records the elapsed time and the container's `memory.peak`.
7. Only after both pass: `:current` moves to the new image and the old one
   becomes `:previous`, `/etc/machsentry-worker/release.json` and `config.json`
   are written, `/opt/machsentry-worker/venv` points at the new venv and the
   units are enabled. They start at the next boot, which the site requests.
   Until then the supervisor and the watchdog stay off: with a stale heartbeat
   the watchdog would power the host off before SSM returns the result. The
   deploy script stops the instance, and the idle alarm does if it cannot.
8. Keeps two releases, two venvs and two images, and removes the build cache. On
   the 20 GB volume, when a build does not fit next to two images, the bootstrap
   removes `:previous` first and reports `previousDropped: true`.

Detailed output stays in `/var/log/machsentry-worker/` on the worker
(`bootstrap-*.log`, `doctor-*.json`, `verify-*/`). The deploy script prints the
progress lines and the JSON summary that `bootstrap.sh` writes last.

Manual runs on the worker, as root:

```bash
bash /opt/machsentry-worker/releases/<commit>/deploy/worker/bootstrap.sh --verify-only
```

`--verify-only` checks `machsentry-analyzer:current` again and changes nothing.
It restarts the supervisor afterwards if it was running, waits for its first
heartbeat, then restarts the watchdog timer if that was running.

## Updating

1. Pause admissions on the site (`scripts/analysis-ops.ts pause`) and wait for
   the queue to empty, or run `worker drain` so the worker claims nothing new.
2. `worker release --commit <new sha>`
3. `worker bootstrap --unlimited-during-build`
4. Resume on the site and run `worker resume` if you drained.

A template change goes through `worker plan` and `worker deploy --yes`. The AMI
stays the same between updates; `--refresh-ami` takes the current Canonical
image and replaces the worker instance, so the script also asks for
`--allow-worker-replacement` and the site env needs the new instance id.

## Rollback

`worker rollback` starts the worker if needed, runs `bootstrap.sh --rollback`
(`:previous` becomes `:current`, `release.json` and the venv link swap back) and
stops it, so the rolled-back release starts at the next boot. Like the
bootstrap, it refuses while a job is in progress and then leaves the instance
on. `/unpacked/analysis/worker/release` keeps the newer upload; run `release`
with the commit you keep before the next bootstrap.

## Operations

- `worker status`: stack, outputs, instance state, CPU credits, maintenance tag,
  release record, worker mode and the last SSM command. It also finishes the
  cleanup of a bootstrap or rollback whose session ended (`--dry-run` only
  prints it).
- `worker logs --since "2 hours ago"`: supervisor and watchdog journal. The
  worker must be running; journald keeps 7 days on its disk.
- `worker drain` / `worker resume`: set `/unpacked/analysis/worker/mode`.
- `worker destroy --confirm-destroy`: disassociates the site profile and
  deletes the stack. The bucket and its objects stay (DeletionPolicy Retain), as
  do the SSM parameters. Set `ANALYSIS_SERVICE` to anything but `aws` first.

Four independent mechanisms stop the worker: the supervisor after 5 idle
minutes, the watchdog (session longer than 2 h 05 min, or a supervisor heartbeat
older than 10 minutes), the CloudWatch alarm (CPU below 2 % for 15 minutes) and
the site reconciler. During a bootstrap or rollback the supervisor and the
watchdog are off and the site holds back; the deploy script and the alarm
remain.

## Costs

`worker preflight` prints the estimate from the stack parameters. With the
defaults and the 40 worker hours per month allowed by `ANALYSIS_LIMITS`:

| Item                                       | US$/month |
| ------------------------------------------ | --------- |
| EC2 `t3a.medium`, 40 h at 0.0376/h         | 1.50      |
| Public IPv4 while running, 40 h at 0.005/h | 0.20      |
| EBS gp3 20 GiB at 0.08/GiB                 | 1.60      |
| CloudWatch alarm                           | 0.10      |
| S3, about 1 GB                             | 0.02      |
| AI stage, hard cap in `ANALYSIS_AI`        | 3.00      |

While the worker is stopped, only the EBS volume (1.60), the alarm and the S3
objects keep costing: the instance hours stop and the public IPv4 address is
released. Prices are us-east-2 list prices of 2026-10-18.

## Security notes

- The bootstrap command carries a presigned URL for one release object, valid
  for one hour; SSM keeps command parameters in its history.
- IMDSv2 is required with a hop limit of 1, and analysis containers have no
  network, so a job cannot reach instance credentials. IMDS also shows the
  instance tags (Name, Project, the maintenance tag), which carry no secrets.
- `AmazonSSMManagedInstanceCore` allows reading any SSM parameter; the worker
  role adds an explicit deny outside `/unpacked/analysis/worker/*` and
  `/unpacked/analysis/openai/*`.
- The analyzer image contains no credentials and no samples, runs as uid 10001
  and gets only the environment listed in contract section 9.

#!/usr/bin/env bash
# Prepare or update the MachSentry analysis worker host for Unpacked. Runs as
# root, normally through SSM Run Command sent by scripts/deploy_machsentry_aws.py:
#
#   bootstrap.sh --release-dir /opt/machsentry-worker/releases/<commit> --commit <commit>
#   bootstrap.sh --rollback      # machsentry-analyzer:previous becomes :current again
#   bootstrap.sh --verify-only   # verify machsentry-analyzer:current; changes nothing
#
# A bootstrap installs the pinned packages and host configuration, installs the
# supervisor venv, builds machsentry-analyzer:<commit>, runs the REA doctor and
# the real REA/Ghidra verifier in an isolated container, and only after both
# pass promotes the image, writes /etc/machsentry-worker/{release,config}.json
# and enables the systemd units, which start at the next boot (requested by the
# site). Every step is idempotent. It refuses to start while a job is in
# progress (--force overrides). While it runs, /run/machsentry-worker-maintenance
# keeps the units from starting; /run is a tmpfs, so a stop or crash midway
# leaves the previous release to start at the next boot.
#
# Detailed output goes to /var/log/machsentry-worker/<mode>-<time>.log. Stdout
# carries short progress lines and, as its last line, one JSON summary.
set -euo pipefail
umask 022

readonly WORKER_ROOT=/opt/machsentry-worker
readonly CONFIG_DIR=/etc/machsentry-worker
readonly STATE_DIR=/var/lib/machsentry-worker
readonly LOG_DIR=/var/log/machsentry-worker
readonly MAINTENANCE_FILE=/run/machsentry-worker-maintenance
readonly HEARTBEAT_FILE=/run/machsentry-worker/heartbeat
readonly GATE_FILE=$WORKER_ROOT/bin/maintenance-gate.py
readonly RELEASE_FILE=$CONFIG_DIR/release.json
readonly PREVIOUS_RELEASE_FILE=$CONFIG_DIR/release.previous.json
readonly CONFIG_FILE=$CONFIG_DIR/config.json
readonly IMAGE_REPO=machsentry-analyzer
readonly ANALYZER_UID=10001
# Versions published in noble-updates on 2026-10-18. Held after install so an
# unattended upgrade never restarts dockerd under a running analysis. When
# Ubuntu supersedes them, a fresh host fails here: update both pins in a release.
readonly DOCKER_VERSION=29.1.3-0ubuntu3~24.04.2
readonly BUILDX_VERSION=0.30.1-0ubuntu1~24.04.1
readonly HOST_PACKAGES=(procps python3-venv e2fsprogs jq ca-certificates apparmor)
readonly WORK_IMAGE_BYTES=$((4 * 1024 * 1024 * 1024))
# Estimated: build stage and final image of about 3.5 GB each, plus downloads
# removed inside the setup layer. Not yet measured on the worker.
readonly MIN_BUILD_FREE_KIB=$((8 * 1024 * 1024))
readonly DOCTOR_TIMEOUT_SECONDS=300
readonly VERIFY_TIMEOUT_SECONDS=3600
readonly STOP_GRACE_SECONDS=30

usage() {
  cat <<'EOF'
Usage: bootstrap.sh --release-dir DIR --commit SHA [--region REGION] [--rebuild] [--force]
       bootstrap.sh --rollback [--force]
       bootstrap.sh --verify-only [--commit SHA] [--force]

--rebuild  build the image again even when machsentry-analyzer:<commit> exists
--force    continue while a job is in progress (its attempt ends as worker_lost)
EOF
}

mode=bootstrap
release_dir=''
commit=''
region=us-east-2
rebuild=0
force=0
while (($#)); do
  case $1 in
    --release-dir) release_dir=${2:?--release-dir needs a value}; shift 2 ;;
    --commit) commit=${2:?--commit needs a value}; shift 2 ;;
    --region) region=${2:?--region needs a value}; shift 2 ;;
    --rollback) mode=rollback; shift ;;
    --verify-only) mode=verify; shift ;;
    --rebuild) rebuild=1; shift ;;
    --force) force=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'bootstrap.sh: unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" -ne 0 ]; then
  printf 'bootstrap.sh: run as root\n' >&2
  exit 2
fi

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]}")")
stamp=$(date -u +%Y%m%dT%H%M%SZ)
started_epoch=$(date +%s)
stage=init
error_message=''
maintenance_entered=0
supervisor_was_active=0
watchdog_was_active=0
venv_incoming=''
active_container=''
verify_root=''
verify_work=''
verify_copy=''
verify_elapsed=null
verify_peak=null
verify_cpu=null
verified_at=''
image_ref=''
image_id=''
built=''
previous_json=null
previous_dropped=false
current_commit=''
previous_commit=''
previous_id=''

install -d -m 0750 "$LOG_DIR"
log_file=$LOG_DIR/$mode-$stamp.log
exec 3>&1 4>&2
exec >>"$log_file" 2>&1

progress() {
  printf '%s %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&3
  printf '== %s %s\n' "$(date -u +%FT%TZ)" "$*"
}

die() {
  error_message=$*
  exit 1
}

failure_summary() {
  # supervisorRunning tells the deploy script that this run stopped nothing, so
  # the instance must stay on for the job the supervisor is running.
  local running=false
  if systemctl is-active --quiet machsentry-supervisor.service 2>/dev/null; then
    running=true
  fi
  python3 -c 'import json, sys; print(json.dumps({"ok": False, "action": sys.argv[1], "stage": sys.argv[2], "error": sys.argv[3], "exitStatus": int(sys.argv[4]), "log": sys.argv[5], "supervisorRunning": sys.argv[6] == "true"}))' \
    "$mode" "$stage" "$error_message" "$1" "$log_file" "$running"
}

cleanup_verify_root() {
  if [ -n "$active_container" ]; then
    docker rm -f "$active_container" >/dev/null 2>&1 || true
    active_container=''
  fi
  [ -n "$verify_root" ] || return 0
  if mountpoint -q "$verify_work"; then
    umount "$verify_work" || umount -l "$verify_work" || true
  fi
  rm -rf "$verify_root"
  verify_root=''
}

wait_heartbeat() { # epoch; gives a restarted supervisor 60 s to write its first heartbeat
  local attempt mtime
  for attempt in $(seq 1 30); do
    mtime=$(stat -c %Y "$HEARTBEAT_FILE" 2>/dev/null || echo 0)
    [ "$mtime" -lt "$1" ] || return 0
    sleep 2
  done
  progress "no supervisor heartbeat 60 s after its restart; the watchdog decides from here"
}

restore_units() { # a verification leaves the units as it found them
  local since
  if [ "$supervisor_was_active" -eq 1 ]; then
    since=$(date +%s)
    systemctl start machsentry-supervisor.service
    # The watchdog powers the host off on a heartbeat older than 10 minutes,
    # and the last one dates from before the verification.
    wait_heartbeat "$since"
  fi
  if [ "$watchdog_was_active" -eq 1 ]; then
    systemctl start machsentry-watchdog.timer
  fi
}

on_exit() {
  local status=$?
  trap - EXIT
  set +e
  cleanup_verify_root
  [ -z "$venv_incoming" ] || rm -rf "$venv_incoming"
  if [ "$maintenance_entered" -eq 1 ]; then
    rm -f "$MAINTENANCE_FILE"
    # After a bootstrap or a rollback the units start at the next boot, which
    # the site requests, and the deploy script stops the host (the idle alarm
    # does otherwise). The watchdog stays off until then: with the supervisor
    # stopped it would power the host off before SSM returns this result.
    if [ "$mode" = verify ]; then
      restore_units
    fi
  fi
  if [ "$status" -ne 0 ]; then
    [ -n "$error_message" ] || error_message="command failed with exit status $status during $stage"
    { printf -- '--- last lines of %s\n' "$log_file"; tail -n 60 "$log_file"; } >&4
    failure_summary "$status" >&3
  fi
  exit "$status"
}
trap on_exit EXIT

acquire_lock() {
  install -d -m 0750 "$STATE_DIR"
  exec 9>"$STATE_DIR/bootstrap.lock"
  flock -n 9 || die "another bootstrap.sh run holds $STATE_DIR/bootstrap.lock"
}

install_if_changed() { # source target mode; succeeds only when the target changed
  if [ -f "$2" ] && cmp -s "$1" "$2"; then
    return 1
  fi
  install -D -m "$3" "$1" "$2"
}

validate_release() {
  stage=release
  [ -n "$release_dir" ] && [ -n "$commit" ] || die "--release-dir and --commit are required"
  [[ $commit =~ ^[0-9a-f]{40}$ ]] || die "--commit must be a full 40-character commit id"
  release_dir=$(realpath -e "$release_dir" 2>/dev/null) || die "release directory not found"
  local path
  # The supervisor unit's ExecCondition runs maintenance-gate.py; systemd skips
  # the unit silently when that file is missing.
  for path in deploy/worker/Dockerfile deploy/worker/maintenance-gate.py scripts/machsentry_setup.py \
    scripts/machsentry-runtime.lock.json scripts/verify-machsentry-ghidra.py worker/requirements.lock.txt; do
    [ -f "$release_dir/$path" ] || die "release is missing $path"
  done
  [ -f "$release_dir/worker/pyproject.toml" ] || [ -f "$release_dir/worker/setup.py" ] ||
    die "release has no installable worker/ package"
  # A release is a git archive: samples, reports and local runtimes are ignored by Git.
  for path in reports .tools .venv-unpack node_modules; do
    [ ! -e "$release_dir/$path" ] || die "release contains $path; publish a git archive of the commit"
  done
  if [ -d "$release_dir/amostras" ] &&
    [ -n "$(find "$release_dir/amostras" -mindepth 1 ! -name README.md -print -quit)" ]; then
    die "release contains files under amostras/; samples never go into a release"
  fi
  progress "release $commit at $release_dir"
}

job_in_progress() { # prints the job in progress; fails when there is none
  local names=''
  if command -v docker >/dev/null 2>&1; then
    # Analysis containers carry the supervisor's machsentry.job label (worker docker_runner.py).
    names=$(docker ps --filter label=machsentry.job --format '{{.Names}}' 2>/dev/null | paste -sd, - || true)
  fi
  if [ -n "$names" ]; then
    printf 'analysis container %s' "$names"
    return 0
  fi
  # The AI review and the publishing run in the supervisor after the container
  # is gone; state.json names that attempt until it ends.
  systemctl is-active --quiet machsentry-supervisor.service 2>/dev/null &&
    python3 -c 'import json, sys
active = json.load(open(sys.argv[1], encoding="utf-8")).get("active")
if not isinstance(active, dict):
    sys.exit(1)
print("job %s attempt %s" % (active.get("jobId"), active.get("attempt")), end="")' "$STATE_DIR/state.json" 2>/dev/null
}

enter_maintenance() {
  stage=maintenance
  local job
  # Checked before anything stops: a refusal leaves the worker as it was.
  if [ "$force" -eq 0 ] && job=$(job_in_progress); then
    die "$job is in progress; drain the worker first or pass --force"
  fi
  if systemctl is-active --quiet machsentry-supervisor.service; then
    supervisor_was_active=1
  fi
  if systemctl is-active --quiet machsentry-watchdog.timer; then
    watchdog_was_active=1
  fi
  touch "$MAINTENANCE_FILE"
  maintenance_entered=1
  systemctl stop machsentry-supervisor.service machsentry-watchdog.timer machsentry-watchdog.service \
    >/dev/null 2>&1 || true
  progress "maintenance on: supervisor and watchdog stopped"
}

apt_get() { # retries: right after boot, apt-daily and cloud-init may hold the apt locks
  local attempt
  for attempt in 1 2 3 4 5; do
    DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 -y -q "$@" </dev/null && return 0
    [ "$attempt" -lt 5 ] || return 1
    sleep 20
  done
}

package_installed() {
  [ "$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null || true)" = installed ]
}

install_packages() {
  stage=packages
  local missing=() package
  package_installed docker.io || missing+=("docker.io=$DOCKER_VERSION")
  package_installed docker-buildx || missing+=("docker-buildx=$BUILDX_VERSION")
  for package in "${HOST_PACKAGES[@]}"; do
    package_installed "$package" || missing+=("$package")
  done
  if ((${#missing[@]})); then
    progress "installing ${missing[*]}"
    apt_get update
    apt_get install --no-install-recommends "${missing[@]}" ||
      die "apt could not install ${missing[*]}; if a pinned version left the archive, update the pins in deploy/worker/bootstrap.sh"
  fi
  apt-mark hold docker.io docker-buildx >/dev/null
  progress "packages: docker.io $(dpkg-query -W -f='${Version}' docker.io), docker-buildx $(dpkg-query -W -f='${Version}' docker-buildx)"
}

configure_host() {
  stage=host
  install -d -m 0755 "$WORKER_ROOT" "$WORKER_ROOT/releases" "$WORKER_ROOT/venvs"
  install -d -m 0750 "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
  install -d -m 0700 "$STATE_DIR/jobs"
  local docker_changed=0
  if install_if_changed "$script_dir/docker-daemon.json" /etc/docker/daemon.json 0644; then
    docker_changed=1
  fi
  if install_if_changed "$script_dir/journald.conf" /etc/systemd/journald.conf.d/machsentry-worker.conf 0644; then
    systemctl restart systemd-journald
  fi
  if [ -d /etc/needrestart ]; then
    install_if_changed "$script_dir/needrestart.conf" /etc/needrestart/conf.d/machsentry-worker.conf 0644 || true
  fi
  # ExecCondition of the supervisor unit; host configuration, so a rollback keeps it.
  install_if_changed "$script_dir/maintenance-gate.py" "$GATE_FILE" 0755 || true
  [ -f "$GATE_FILE" ] || die "could not install $GATE_FILE"
  systemctl enable docker.service >/dev/null 2>&1
  if [ "$docker_changed" -eq 1 ]; then
    systemctl restart docker.service
  else
    systemctl start docker.service
  fi
  local attempt
  for attempt in $(seq 1 30); do
    docker info >/dev/null 2>&1 && break
    [ "$attempt" -lt 30 ] || die "dockerd did not answer after 60 s"
    sleep 2
  done
  progress "host configured: daemon.json, journald 7 days/200M, maintenance gate, directories"
}

install_supervisor() {
  stage=supervisor
  local venv=$WORKER_ROOT/venvs/$commit marker digest next isolation=()
  marker=$venv/.machsentry-complete
  digest=$(cd "$release_dir" && find worker -type f ! -path '*/__pycache__/*' -print0 | sort -z |
    xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
  if [ -f "$marker" ] && [ "$(cat "$marker")" = "$digest" ]; then
    progress "supervisor venv for $commit already installed"
    return
  fi
  # Built aside and renamed into place once complete: /opt/machsentry-worker/venv
  # may point at $venv, which stays usable when a download or install fails.
  venv_incoming=$(mktemp -d "$WORKER_ROOT/venvs/.incoming-XXXXXX")
  next=$venv_incoming/venv
  python3 -m venv "$next"
  PIP_NO_CACHE_DIR=1 "$next/bin/python" -m pip install --disable-pip-version-check --no-input \
    --require-hashes --only-binary=:all: -r "$release_dir/worker/requirements.lock.txt" </dev/null
  # Hash-pinned build backend from the lock when present; pip's isolated build otherwise.
  if "$next/bin/python" -c 'import setuptools' 2>/dev/null; then
    isolation=(--no-build-isolation)
  fi
  # pip builds a local directory in place (build/, *.egg-info); building a copy
  # keeps the release a plain git archive and the digest above stable.
  cp -a "$release_dir/worker" "$venv_incoming/source"
  PIP_NO_CACHE_DIR=1 "$next/bin/python" -m pip install --disable-pip-version-check --no-input \
    --no-deps "${isolation[@]}" "$venv_incoming/source" </dev/null
  "$next/bin/python" -c 'import importlib.util, sys; sys.exit(0 if all(importlib.util.find_spec(m) for m in ("machsentry_worker.supervisor", "machsentry_worker.watchdog")) else 1)' ||
    die "the worker package lacks machsentry_worker.supervisor or machsentry_worker.watchdog"
  printf '%s\n' "$digest" >"$next/.machsentry-complete"
  if [ -e "$venv" ]; then
    mv -T "$venv" "$venv_incoming/replaced"
  fi
  mv -T "$next" "$venv"
  rm -rf "$venv_incoming"
  venv_incoming=''
  progress "supervisor venv installed at $venv"
}

prune_images() { # keeps :current, :previous and the commits named in the release files
  local keep_current keep_previous tag
  keep_current=$(jq -r '.commit // empty' "$RELEASE_FILE" 2>/dev/null || true)
  keep_previous=$(jq -r '.commit // empty' "$PREVIOUS_RELEASE_FILE" 2>/dev/null || true)
  docker image ls "$IMAGE_REPO" --format '{{.Tag}}' | while read -r tag; do
    [[ $tag =~ ^[0-9a-f]{40}$ ]] || continue
    [ "$tag" = "$keep_current" ] || [ "$tag" = "$keep_previous" ] || [ "$tag" = "$commit" ] ||
      docker image rm "$IMAGE_REPO:$tag" >/dev/null || true
  done
  docker image prune -f >/dev/null || true
  docker builder prune -af >/dev/null || true
}

free_kib() {
  df --output=avail -k /var/lib/docker | tail -n 1 | tr -d ' '
}

ensure_disk_space() {
  stage=disk
  if (($(free_kib) < MIN_BUILD_FREE_KIB)); then
    progress "less than 8 GiB free; pruning old images and build cache"
    prune_images
  fi
  if (($(free_kib) < MIN_BUILD_FREE_KIB)) && docker image inspect "$IMAGE_REPO:previous" >/dev/null 2>&1; then
    # Two analyzer images and a build may not fit the 20 GB volume. A failed
    # build still leaves :current in place; only the rollback target goes.
    progress "still short of space; removing $IMAGE_REPO:previous, so rollback is unavailable until the next release"
    rm -f "$PREVIOUS_RELEASE_FILE"
    docker image rm "$IMAGE_REPO:previous" >/dev/null || true
    previous_dropped=true
    prune_images
  fi
  (($(free_kib) >= MIN_BUILD_FREE_KIB)) || die "the build needs 8 GiB free under /var/lib/docker; $(free_kib) KiB available"
}

build_image() {
  stage=build
  image_ref=$IMAGE_REPO:$commit
  local revision lock=$release_dir/scripts/machsentry-runtime.lock.json
  revision=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image_ref" 2>/dev/null || true)
  if [ "$rebuild" -eq 0 ] && [ "$revision" = "$commit" ]; then
    built=reused
    progress "image $image_ref exists; reusing it (--rebuild builds again)"
  else
    progress "building $image_ref; build output goes to $log_file"
    local machsentry_version jdk
    machsentry_version=$(python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' \
      "$release_dir/macos_static/pyproject.toml")
    jdk=$(jq -r .versions.jdk "$lock")
    DOCKER_BUILDKIT=1 docker build --progress plain \
      --file "$release_dir/deploy/worker/Dockerfile" \
      --tag "$image_ref" \
      --build-arg "MACHSENTRY_COMMIT=$commit" \
      --build-arg "MACHSENTRY_VERSION=$machsentry_version" \
      --build-arg "REA_VERSION=$(jq -r .version "$release_dir/package.json")" \
      --build-arg "GHIDRA_VERSION=$(jq -r .versions.ghidra "$lock")" \
      --build-arg "JDK_VERSION=$jdk" \
      --build-arg "JDK_DIR_VERSION=${jdk//+/-}" \
      --build-arg "NODE_VERSION=$(jq -r .versions.node "$lock")" \
      "$release_dir" </dev/null || die "docker build failed"
    built=built
  fi
  image_id=$(docker image inspect -f '{{.Id}}' "$image_ref")
  progress "image $image_ref is $image_id"
}

run_analyzer() { # name timeout-seconds stdout-file image command...
  local name=$1 limit=$2 output=$3 image=$4 status
  shift 4
  docker rm -f "$name" >/dev/null 2>&1 || true
  active_container=$name
  # Same isolation as an analysis job (contract section 9); no input file here.
  docker run --detach --name "$name" \
    --network none --read-only --init --user "$ANALYZER_UID:$ANALYZER_UID" \
    --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 \
    --memory 3g --memory-swap 3g --cpus 2 \
    --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --mount "type=bind,source=$verify_work,target=/work" \
    --env HOME=/work/home --env TMPDIR=/work/tmp \
    --env GHIDRA_HEADLESS_MAXMEM=1536M --env REA_GHIDRA_STARTUP_TIMEOUT_MS=780000 \
    --env PYTHONDONTWRITEBYTECODE=1 --env LANG=C.UTF-8 \
    --label org.unpackedlab.machsentry.role=bootstrap-verification \
    "$image" "$@" >/dev/null || return 125
  if ! status=$(timeout "$limit" docker wait "$name"); then
    progress "$name passed its ${limit} s deadline; sending SIGINT"
    docker kill --signal SIGINT "$name" >/dev/null 2>&1 || true
    timeout "$STOP_GRACE_SECONDS" docker wait "$name" >/dev/null 2>&1 || true
    status=124
  fi
  docker logs "$name" >"$output" 2>"$output.stderr" || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  active_container=''
  return "$status"
}

verify_image() { # image reference
  stage=verify
  local image=$1 rc=0 started finished
  verify_root=$(mktemp -d "$STATE_DIR/verify.XXXXXX")
  verify_work=$verify_root/work
  mkdir "$verify_work"
  truncate -s "$WORK_IMAGE_BYTES" "$verify_root/work.img"
  mkfs.ext4 -q -F -m 0 -E "root_owner=$ANALYZER_UID:$ANALYZER_UID" "$verify_root/work.img"
  mount -o loop,nosuid,nodev "$verify_root/work.img" "$verify_work"
  install -d -o "$ANALYZER_UID" -g "$ANALYZER_UID" -m 0700 "$verify_work/home" "$verify_work/tmp"

  # The doctor runs node directly, as the supervisor does, so it checks the image's
  # own PATH, JAVA_HOME and GHIDRA_INSTALL_DIR; the verifier goes through
  # scripts/machsentry_run.py and .tools/runtime.json.
  progress "doctor: REA Ghidra provider in $image"
  run_analyzer "machsentry-bootstrap-doctor-$stamp" "$DOCTOR_TIMEOUT_SECONDS" "$verify_root/doctor.json" "$image" \
    node scripts/rea.mjs doctor --provider ghidra --json || rc=$?
  cp "$verify_root/doctor.json" "$LOG_DIR/doctor-$stamp.json" 2>/dev/null || true
  [ "$rc" -eq 0 ] && jq -e '.healthy == true' "$verify_root/doctor.json" >/dev/null 2>&1 ||
    die "REA doctor reported the Ghidra provider unhealthy (exit $rc); see $LOG_DIR/doctor-$stamp.json"

  progress "verifier: real REA/Ghidra decompilation and MachSentry report on inert fixtures"
  started=$(date +%s%N)
  # memory.peak and cpu.stat are read inside the container, before its cgroup goes away.
  run_analyzer "machsentry-bootstrap-verify-$stamp" "$VERIFY_TIMEOUT_SECONDS" "$verify_root/verify.stdout" "$image" \
    sh -c 'python3 scripts/verify-machsentry-ghidra.py --output /work/verify; status=$?; cat /sys/fs/cgroup/memory.peak >/work/memory.peak 2>/dev/null; cat /sys/fs/cgroup/cpu.stat >/work/cpu.stat 2>/dev/null; exit $status' ||
    rc=$?
  finished=$(date +%s%N)
  verified_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  verify_elapsed=$(awk -v ns=$((finished - started)) 'BEGIN { printf "%.3f", ns / 1e9 }')
  verify_peak=$(tr -d '[:space:]' <"$verify_work/memory.peak" 2>/dev/null || true)
  [[ $verify_peak =~ ^[0-9]+$ ]] || verify_peak=null
  verify_cpu=$(awk '$1 == "usage_usec" { printf "%.3f", $2 / 1e6 }' "$verify_work/cpu.stat" 2>/dev/null || true)
  [ -n "$verify_cpu" ] || verify_cpu=null
  verify_copy=$LOG_DIR/verify-$stamp
  mkdir -p "$verify_copy"
  cp "$verify_root/verify.stdout" "$verify_root/verify.stdout.stderr" "$verify_copy/" 2>/dev/null || true
  if [ -d "$verify_work/verify" ]; then
    cp -r --no-preserve=ownership "$verify_work/verify/." "$verify_copy/" || true
  fi
  [ "$rc" -eq 0 ] || die "verification failed (exit $rc after ${verify_elapsed} s); output retained in $verify_copy"
  progress "verified in ${verify_elapsed} s, peak memory ${verify_peak} bytes"
  cleanup_verify_root
}

write_json() { # target mode; JSON on stdin, replaced atomically
  local tmp
  tmp=$(mktemp "$1.XXXXXX")
  cat >"$tmp"
  chmod "$2" "$tmp"
  mv -f "$tmp" "$1"
}

install_units() { # directory holding the unit files
  local unit
  for unit in machsentry-supervisor.service machsentry-watchdog.service machsentry-watchdog.timer; do
    install_if_changed "$1/$unit" "/etc/systemd/system/$unit" 0644 || true
  done
  systemctl daemon-reload
  systemctl enable machsentry-supervisor.service machsentry-watchdog.timer >/dev/null 2>&1
}

activate_venv() { # commit
  ln -sfn "venvs/$1" "$WORKER_ROOT/venv.next"
  mv -Tf "$WORKER_ROOT/venv.next" "$WORKER_ROOT/venv"
}

promote() {
  stage=promote
  local current_id built_at
  current_id=$(docker image inspect -f '{{.Id}}' "$IMAGE_REPO:current" 2>/dev/null || true)
  if [ -n "$current_id" ] && [ "$current_id" != "$image_id" ]; then
    docker tag "$IMAGE_REPO:current" "$IMAGE_REPO:previous"
    if [ -f "$RELEASE_FILE" ]; then
      write_json "$PREVIOUS_RELEASE_FILE" 0640 <"$RELEASE_FILE"
    fi
  fi
  if [ -f "$PREVIOUS_RELEASE_FILE" ]; then
    previous_json=$(jq -c '{commit, image_id}' "$PREVIOUS_RELEASE_FILE")
  fi
  docker tag "$image_ref" "$IMAGE_REPO:current"
  built_at=$(docker image inspect -f '{{.Created}}' "$image_ref")
  jq -n --arg commit "$commit" --arg image_id "$image_id" --arg built_at "$built_at" \
    --arg verified_at "$verified_at" --argjson elapsed "$verify_elapsed" --argjson peak "$verify_peak" \
    '{commit: $commit, image_id: $image_id, built_at: $built_at, verified_at: $verified_at,
      verify: {elapsed: $elapsed, peakMemoryBytes: $peak}}' | write_json "$RELEASE_FILE" 0640
  jq -n --arg region "$region" --arg image "$IMAGE_REPO:current" --arg release "$RELEASE_FILE" \
    --arg heartbeat "$HEARTBEAT_FILE" \
    '{region: $region, ssmPrefix: "/unpacked/analysis", stateDir: "/var/lib/machsentry-worker",
      image: $image, releaseFile: $release, heartbeatFile: $heartbeat}' |
    write_json "$CONFIG_FILE" 0640
  activate_venv "$commit"
  install_units "$release_dir/deploy/worker/systemd"
  rm -f "$STATE_DIR/bootstrap-pending"
  progress "promoted $image_ref to :current; units enabled for the next boot"
}

validate_rollback() {
  stage=rollback
  command -v docker >/dev/null 2>&1 || die "docker is not installed; bootstrap a release first"
  [ -f "$RELEASE_FILE" ] && [ -f "$PREVIOUS_RELEASE_FILE" ] || die "no previous release is recorded"
  current_commit=$(jq -r .commit "$RELEASE_FILE")
  previous_commit=$(jq -r .commit "$PREVIOUS_RELEASE_FILE")
  previous_id=$(docker image inspect -f '{{.Id}}' "$IMAGE_REPO:previous" 2>/dev/null) ||
    die "$IMAGE_REPO:previous does not exist"
  [ "$previous_id" = "$(jq -r .image_id "$PREVIOUS_RELEASE_FILE")" ] ||
    die "$IMAGE_REPO:previous does not match $PREVIOUS_RELEASE_FILE; bootstrap the wanted commit instead"
  [ -f "$WORKER_ROOT/venvs/$previous_commit/.machsentry-complete" ] ||
    die "the supervisor venv of $previous_commit is missing; bootstrap that commit instead"
}

rollback_release() {
  stage=rollback
  docker tag "$IMAGE_REPO:current" "$IMAGE_REPO:rollback-swap"
  docker tag "$IMAGE_REPO:previous" "$IMAGE_REPO:current"
  docker tag "$IMAGE_REPO:rollback-swap" "$IMAGE_REPO:previous"
  docker image rm "$IMAGE_REPO:rollback-swap" >/dev/null
  local swap
  swap=$(mktemp "$CONFIG_DIR/release.swap.XXXXXX")
  cp "$RELEASE_FILE" "$swap"
  write_json "$RELEASE_FILE" 0640 <"$PREVIOUS_RELEASE_FILE"
  write_json "$PREVIOUS_RELEASE_FILE" 0640 <"$swap"
  rm -f "$swap"
  activate_venv "$previous_commit"
  if [ -d "$WORKER_ROOT/releases/$previous_commit/deploy/worker/systemd" ]; then
    install_units "$WORKER_ROOT/releases/$previous_commit/deploy/worker/systemd"
  fi
  commit=$previous_commit
  image_ref=$IMAGE_REPO:current
  image_id=$previous_id
  previous_json=$(jq -c '{commit, image_id}' "$PREVIOUS_RELEASE_FILE")
  progress "rolled back from $current_commit to $previous_commit"
}

cleanup_old() {
  stage=cleanup
  local keep_current keep_previous path name
  keep_current=$(jq -r '.commit // empty' "$RELEASE_FILE" 2>/dev/null || true)
  keep_previous=$(jq -r '.commit // empty' "$PREVIOUS_RELEASE_FILE" 2>/dev/null || true)
  prune_images
  for path in "$WORKER_ROOT"/releases/* "$WORKER_ROOT"/venvs/*; do
    name=$(basename "$path")
    name=${name%.sha256}
    [[ $name =~ ^[0-9a-f]{40}$ ]] || continue
    [ "$name" = "$keep_current" ] || [ "$name" = "$keep_previous" ] || rm -rf "$path"
  done
  find "$WORKER_ROOT/releases" "$WORKER_ROOT/venvs" -maxdepth 1 -name '.incoming-*' -mmin +60 -exec rm -rf {} + 2>/dev/null || true
  find "$STATE_DIR" -maxdepth 1 -name 'verify.*' -mmin +60 -exec rm -rf {} + 2>/dev/null || true
  ls -1dt "$LOG_DIR"/verify-* 2>/dev/null | tail -n +6 | xargs -r rm -rf
  ls -1t "$LOG_DIR"/*.log "$LOG_DIR"/doctor-*.json 2>/dev/null | tail -n +31 | xargs -r rm -f
}

package_versions() {
  local out='{}' package version
  for package in docker.io docker-buildx containerd runc python3 procps e2fsprogs jq; do
    version=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)
    out=$(jq -c --arg p "$package" --arg v "$version" '. + {($p): (if $v == "" then null else $v end)}' <<<"$out")
  done
  printf '%s' "$out"
}

summary() {
  stage=summary
  local root
  root=$(df -B1 --output=size,avail / | tail -n 1)
  jq -cn --arg action "$mode" --arg commit "$commit" --arg image "$image_ref" --arg imageId "$image_id" \
    --arg build "$built" --arg log "$log_file" --arg output "$verify_copy" \
    --argjson elapsed "$verify_elapsed" --argjson peak "$verify_peak" --argjson cpu "$verify_cpu" \
    --argjson previous "$previous_json" --argjson previousDropped "$previous_dropped" \
    --argjson packages "$(package_versions)" \
    --argjson rootBytes "$(awk '{ print $1 }' <<<"$root")" --argjson freeBytes "$(awk '{ print $2 }' <<<"$root")" \
    --argjson seconds $(($(date +%s) - started_epoch)) \
    '{ok: true, action: $action, commit: $commit, image: $image, imageId: $imageId,
      build: (if $build == "" then null else $build end), previous: $previous, previousDropped: $previousDropped,
      verify: (if $output == "" then null else {elapsed: $elapsed, peakMemoryBytes: $peak, cpuSeconds: $cpu,
        doctorHealthy: true, output: $output} end),
      packages: $packages, disk: {rootBytes: $rootBytes, freeBytes: $freeBytes},
      seconds: $seconds, log: $log}' >&3
}

acquire_lock
case $mode in
  bootstrap)
    validate_release
    enter_maintenance
    install_packages
    configure_host
    install_supervisor
    ensure_disk_space
    build_image
    verify_image "$image_ref"
    promote
    cleanup_old
    ;;
  rollback)
    validate_rollback
    enter_maintenance
    rollback_release
    ;;
  verify)
    stage=verify
    command -v docker >/dev/null 2>&1 || die "docker is not installed; bootstrap a release first"
    if [ -n "$commit" ]; then
      [[ $commit =~ ^[0-9a-f]{40}$ ]] || die "--commit must be a full 40-character commit id"
      image_ref=$IMAGE_REPO:$commit
    else
      image_ref=$IMAGE_REPO:current
      commit=$(jq -r '.commit // empty' "$RELEASE_FILE" 2>/dev/null || true)
    fi
    image_id=$(docker image inspect -f '{{.Id}}' "$image_ref" 2>/dev/null) || die "$image_ref does not exist"
    enter_maintenance
    verify_image "$image_ref"
    ;;
esac
summary

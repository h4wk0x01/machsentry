# MachSentry analyzer image for the Unpacked analysis worker.
#
# deploy/worker/bootstrap.sh builds it on the worker host from a release
# archive (git archive of one commit), with the repository root as context:
#
#   docker build -f deploy/worker/Dockerfile -t machsentry-analyzer:<commit> .
#
# The final stage holds the REA build, the pinned Ghidra/JDK/Node runtimes and
# the MachSentry venv under /opt/machsentry, runs as uid 10001 and contains no
# credentials or samples. Each analysis runs in a fresh container with
# --network none --read-only (deploy/worker/README.md, contract section 9).
#
# Base: official ubuntu:24.04, linux/amd64 manifest, pinned by digest on
# 2026-10-18 (multi-arch index sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac,
# image created 2026-10-02). Every stage derives from this one FROM, so the
# build and final stages share the same Python interpreter.
FROM ubuntu:24.04@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc AS base
ENV LANG=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 procps \
 && rm -rf /var/lib/apt/lists/*

FROM base AS build
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENV HUSKY=0 \
    TURBO_TELEMETRY_DISABLED=1 \
    DO_NOT_TRACK=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    npm_config_audit=false \
    npm_config_fund=false \
    npm_config_update_notifier=false \
    npm_config_cache=/tmp/npm-cache
WORKDIR /opt/machsentry
COPY . .
# Setup downloads the locked runtimes, runs npm ci, builds REA, installs the
# MachSentry venv and runs the Ghidra doctor. Caches and archives are removed
# in the same layer so the build stage does not keep a second copy of them.
RUN env -u JAVA_HOME -u GHIDRA_INSTALL_DIR python3 scripts/machsentry_setup.py \
 && rm -rf .tools/downloads .turbo .cache node_modules/.cache /tmp/npm-cache /root/.cache /root/.npm \
 && chmod -R a+rX,go-w /opt/machsentry
RUN python3 -c "import json, os; c = json.load(open('.tools/runtime.json')); paths = [c['executables']['node'], c['executables']['npm_cli'], c['environment']['GHIDRA_INSTALL_DIR'], c['environment']['JAVA_HOME']]; bad = [p for p in paths if not p.startswith('/opt/machsentry/') or not os.path.exists(p)]; assert c['host'] == {'platform': 'linux', 'arch': 'x64'}, c['host']; assert not bad, bad; assert os.access(os.path.join(c['environment']['JAVA_HOME'], 'bin', 'java'), os.X_OK)" \
 && test -f dist/mcp/main.js \
 && test -x .venv-unpack/bin/python \
 && .venv-unpack/bin/python -m compileall -q macos_static/machsentry \
 && python3 -m compileall -q scripts/machsentry_setup.py scripts/machsentry_run.py scripts/verify-machsentry-ghidra.py

FROM base AS analyzer
# Runtime versions from scripts/machsentry-runtime.lock.json (bootstrap.sh passes
# them); JDK_DIR_VERSION is JDK_VERSION with "+" replaced by "-", as setup names
# the directory. The check below fails the build if these paths drift from the
# runtime.json that setup wrote.
ARG GHIDRA_VERSION=12.1.4
ARG JDK_VERSION=21.0.12.1+1
ARG JDK_DIR_VERSION=21.0.12.1-1
ARG NODE_VERSION=24.18.0
RUN groupadd --gid 10001 machsentry \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /work/home --shell /usr/sbin/nologin machsentry
COPY --from=build /opt/machsentry /opt/machsentry
# `python` and `python3` resolve to the MachSentry venv and `node` to the pinned
# Node, so the worker can run `python -m machsentry` and `node scripts/rea.mjs`.
ENV GHIDRA_INSTALL_DIR=/opt/machsentry/.tools/ghidra-${GHIDRA_VERSION}/ghidra_${GHIDRA_VERSION}_PUBLIC \
    JAVA_HOME=/opt/machsentry/.tools/jdk-linux-x64-${JDK_DIR_VERSION}/jdk-${JDK_VERSION} \
    REA_ANALYSIS_PROVIDER=ghidra
ENV PATH=/opt/machsentry/.venv-unpack/bin:/opt/machsentry/.tools/node-linux-x64-${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64/bin:${JAVA_HOME}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /opt/machsentry
RUN python3 -c "import json, os, shutil, sys; c = json.load(open('.tools/runtime.json')); e = c['environment']; wanted = {'GHIDRA_INSTALL_DIR': e['GHIDRA_INSTALL_DIR'], 'JAVA_HOME': e['JAVA_HOME'], 'REA_ANALYSIS_PROVIDER': e['REA_ANALYSIS_PROVIDER']}; drift = {k: (os.environ.get(k), v) for k, v in wanted.items() if os.environ.get(k) != v}; assert not drift, drift; assert shutil.which('node') == c['executables']['node'], shutil.which('node'); assert sys.prefix == '/opt/machsentry/.venv-unpack', sys.prefix; import machsentry"
USER 10001:10001
# The supervisor stops a job with SIGINT, waits 30 s, then removes the container.
STOPSIGNAL SIGINT
CMD ["python3", "scripts/machsentry_run.py", "rea", "doctor", "--provider", "ghidra", "--json"]
ARG MACHSENTRY_COMMIT=unknown
ARG MACHSENTRY_VERSION=unknown
ARG REA_VERSION=unknown
LABEL org.opencontainers.image.title="machsentry-analyzer" \
      org.opencontainers.image.description="MachSentry static Mach-O analyzer (REA MCP and Ghidra) for the Unpacked worker" \
      org.opencontainers.image.source="https://github.com/h4wk0x01/machsentry" \
      org.opencontainers.image.revision="${MACHSENTRY_COMMIT}" \
      org.opencontainers.image.version="${MACHSENTRY_VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:24.04" \
      org.opencontainers.image.base.digest="sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc" \
      org.unpackedlab.machsentry.rea="${REA_VERSION}" \
      org.unpackedlab.machsentry.ghidra="${GHIDRA_VERSION}" \
      org.unpackedlab.machsentry.jdk="${JDK_VERSION}" \
      org.unpackedlab.machsentry.node="${NODE_VERSION}"

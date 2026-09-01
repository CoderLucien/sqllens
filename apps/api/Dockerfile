ARG PYTHON_BASE=python:3.12.14-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579
ARG SOURCE_REVISION=unverified
ARG SOURCE_GIT_TREE=unverified
ARG DOCKERFILE_GIT_BLOB=unverified
ARG SUPPLY_CHAIN_VERIFIER_GIT_BLOB=unverified

FROM node:22.22.1-bookworm-slim@sha256:4f77a690f2f8946ab16fe1e791a3ac0667ae1c3575c3e4d0d4589e9ed5bfaf3d AS web-build

WORKDIR /build/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web/ ./
RUN npm run build

FROM ${PYTHON_BASE} AS python-artifacts

ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /supply-chain
COPY requirements/runtime.lock requirements/build.lock ./requirements/
RUN python -m pip download \
        --no-cache-dir \
        --timeout=120 \
        --retries=10 \
        --only-binary=:all: \
        --require-hashes \
        --dest /wheelhouse/runtime \
        -r requirements/runtime.lock \
    && python -m pip download \
        --no-cache-dir \
        --timeout=120 \
        --retries=10 \
        --only-binary=:all: \
        --require-hashes \
        --dest /wheelhouse/build \
        -r requirements/build.lock

FROM ${PYTHON_BASE} AS python-app-build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

ARG SOURCE_DATE_EPOCH=315532800
ARG SQLLENS_OFFLINE_PROOF_NONCE=stable
WORKDIR /build
COPY --from=python-artifacts /wheelhouse /wheelhouse
COPY requirements/build.lock requirements/build.lock
RUN test -n "$SQLLENS_OFFLINE_PROOF_NONCE" \
    && python -m pip install \
        --no-cache-dir \
        --no-compile \
        --no-index \
        --find-links=/wheelhouse/build \
        --only-binary=:all: \
        --require-hashes \
        -r requirements/build.lock

COPY pyproject.toml ./
COPY apps/api/ apps/api/
RUN python -m pip wheel \
        --no-cache-dir \
        --no-build-isolation \
        --no-deps \
        --no-index \
        --wheel-dir /wheelhouse/app \
        .

FROM ${PYTHON_BASE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SQLLENS_DATA_DIR=/data \
    SQLLENS_SECRETS_DIR=/secrets \
    SQLLENS_WEB_DIST_DIR=/app/static

ARG SQLLENS_OFFLINE_PROOF_NONCE=stable
ARG SOURCE_REVISION
ARG SOURCE_GIT_TREE
ARG DOCKERFILE_GIT_BLOB
ARG SUPPLY_CHAIN_VERIFIER_GIT_BLOB
WORKDIR /app
COPY requirements/runtime.lock requirements/runtime.lock
COPY --from=python-artifacts /wheelhouse/runtime /wheelhouse/runtime
COPY --from=python-app-build /wheelhouse/app /wheelhouse/app
COPY --from=python-app-build /build/apps/api/entrypoint.sh /tmp/sqllens-entrypoint
RUN test -n "$SQLLENS_OFFLINE_PROOF_NONCE" \
    && python -m pip install \
        --no-cache-dir \
        --no-compile \
        --no-index \
        --find-links=/wheelhouse/runtime \
        --only-binary=:all: \
        --require-hashes \
        -r requirements/runtime.lock \
    && python -m pip install \
        --no-cache-dir \
        --no-build-isolation \
        --no-compile \
        --no-deps \
        --no-index \
        /wheelhouse/app/sqllens_p0-*.whl \
    && python -m pip check \
    && rm -rf /wheelhouse \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sqllens \
    && install -d -m 0700 -o sqllens -g sqllens /data /secrets \
    && install -d -m 0755 -o sqllens -g sqllens /app/static \
    && install -m 0755 /tmp/sqllens-entrypoint /usr/local/bin/sqllens-entrypoint \
    && rm /tmp/sqllens-entrypoint

LABEL org.opencontainers.image.base.name="python:3.12.14-slim-bookworm" \
      org.opencontainers.image.base.digest="sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      dev.sqllens.source.git-tree="${SOURCE_GIT_TREE}" \
      dev.sqllens.build.dockerfile.git-blob="${DOCKERFILE_GIT_BLOB}" \
      dev.sqllens.build.verifier.git-blob="${SUPPLY_CHAIN_VERIFIER_GIT_BLOB}"

COPY --from=web-build --chown=sqllens:sqllens /build/apps/web/dist/ /app/static/

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sqllens-entrypoint"]
CMD ["web-api"]

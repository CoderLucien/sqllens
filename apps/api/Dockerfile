FROM node:22.22.1-bookworm-slim@sha256:4f77a690f2f8946ab16fe1e791a3ac0667ae1c3575c3e4d0d4589e9ed5bfaf3d AS web-build

WORKDIR /build/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web/ ./
RUN npm run build

FROM python:3.12.3-slim-bookworm@sha256:afc139a0a640942491ec481ad8dda10f2c5b753f5c969393b12480155fe15a63 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SQLLENS_DATA_DIR=/data \
    SQLLENS_WEB_DIST_DIR=/app/static

WORKDIR /app
COPY requirements/runtime.lock requirements/runtime.lock
RUN python -m pip install --no-cache-dir -r requirements/runtime.lock

COPY pyproject.toml ./
COPY apps/api/ apps/api/
RUN python -m pip install --no-cache-dir --no-deps . \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin sqllens \
    && mkdir -p /data /app/static \
    && chown -R sqllens:sqllens /data /app/static \
    && install -m 0755 apps/api/entrypoint.sh /usr/local/bin/sqllens-entrypoint

COPY --from=web-build --chown=sqllens:sqllens /build/apps/web/dist/ /app/static/

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/sqllens-entrypoint"]
CMD ["web-api"]

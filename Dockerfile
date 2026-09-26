# syntax=docker/dockerfile:1
# One deployment image. SDK-v1 mail engine and FastMCP auth remain isolated.
# Keep the multi-architecture base tags and manifest digests together when patching.
FROM ghcr.io/astral-sh/uv:0.11.29@sha256:eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc AS uv
FROM python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26 AS email-builder
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/email
WORKDIR /build/email
COPY uv.lock pyproject.toml README.md LICENSE ./
RUN uv sync --frozen --no-install-project --no-dev
COPY mcp_email_server ./mcp_email_server
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26 AS remote-builder
RUN python -m venv /opt/remote
WORKDIR /build/remote
COPY remote/requirements-runtime.txt ./
RUN /opt/remote/bin/pip install --no-cache-dir --require-hashes -r requirements-runtime.txt
COPY remote/pyproject.toml ./
COPY remote/src ./src
RUN /opt/remote/bin/pip install --no-cache-dir --no-deps .

FROM python:3.13.15-slim-bookworm@sha256:2325bb286ec344af3e5898cc224b5844e2707ac6e26b1632516fd3edc84a5e26 AS runtime
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/yusoofsh/mcp-email-server" \
      org.opencontainers.image.description="Email MCP with FastMCP OAuth and Argon2id local login" \
      org.opencontainers.image.licenses="BSD-3-Clause" \
      org.opencontainers.image.revision="${VCS_REF}"
RUN apt-get update && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 mcp && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /data mcp \
 && mkdir -p /data/auth /data/mail /data/downloads \
 && chown -R 10001:10001 /data && chmod 700 /data /data/auth /data/mail /data/downloads
COPY --from=email-builder /opt/email /opt/email
COPY --from=remote-builder /opt/remote /opt/remote
ENV PATH="/opt/remote/bin:/opt/email/bin:$PATH" \
    HOME=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    MCP_EMAIL_COMMAND=/opt/email/bin/mcp-email-server \
    MCP_EMAIL_SERVER_CONFIG_PATH=/data/mail/config.toml \
    MCP_AUTH_STATE_PATH=/data/auth/oauth.sqlite3 MCP_HOST=0.0.0.0 MCP_PORT=9557
WORKDIR /data
USER 10001:10001
EXPOSE 9557
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/opt/remote/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9557/healthz', timeout=3).read()"]
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/remote/bin/email-mcp-remote"]
CMD ["serve"]

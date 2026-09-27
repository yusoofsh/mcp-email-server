# syntax=docker/dockerfile:1
# One deployment image. SDK-v1 mail engine and FastMCP auth remain isolated.
# Keep the multi-architecture base tags and manifest digests together when patching.
FROM ghcr.io/astral-sh/uv:0.11.29@sha256:eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc AS uv
# The official multi-architecture index digest is shared by every Python stage.
FROM python:3.13.15-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS email-builder
COPY --from=uv /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/email
WORKDIR /build/email
COPY uv.lock pyproject.toml README.md LICENSE ./
RUN uv sync --frozen --no-install-project --no-dev
COPY mcp_email_server ./mcp_email_server
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13.15-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS remote-builder
RUN python -m venv /opt/remote
WORKDIR /build/remote
COPY remote/requirements-runtime.txt ./
RUN /opt/remote/bin/pip install --no-cache-dir --require-hashes -r requirements-runtime.txt
COPY remote/pyproject.toml ./
COPY remote/src ./src
RUN /opt/remote/bin/pip install --no-cache-dir --no-deps . \
 && find /opt/remote/lib/python3.13/site-packages -mindepth 1 -maxdepth 1 \
      \( -name 'pip' -o -name 'pip-*.dist-info' \
         -o -name 'setuptools' -o -name 'setuptools-*.dist-info' \
         -o -name 'pkg_resources' -o -name '_distutils_hack' \
         -o -name 'distutils-precedence.pth' \) \
      -exec rm -rf '{}' + \
 && rm -f /opt/remote/bin/pip /opt/remote/bin/pip3 /opt/remote/bin/pip3.13 \
          /opt/remote/bin/easy_install /opt/remote/bin/easy_install-3.13

FROM python:3.13.15-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS runtime
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/yusoofsh/mcp-email-server" \
      org.opencontainers.image.description="Email MCP with FastMCP OAuth and Argon2id local login" \
      org.opencontainers.image.licenses="BSD-3-Clause" \
      org.opencontainers.image.revision="${VCS_REF}"
RUN apt-get update && apt-get install -y --no-install-recommends tini \
 && apt-get install -y --no-install-recommends --only-upgrade openssl tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 mcp && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /data mcp \
 && mkdir -p /data/auth /data/mail /data/downloads \
 && chown -R 10001:10001 /data && chmod 700 /data /data/auth /data/mail /data/downloads
# pip and setuptools are builder-only; retain the Python standard library and app venv.
RUN find /usr/local/lib/python3.13/site-packages -mindepth 1 -maxdepth 1 \
      \( -name 'pip' -o -name 'pip-*.dist-info' \
         -o -name 'setuptools' -o -name 'setuptools-*.dist-info' \
         -o -name 'pkg_resources' -o -name '_distutils_hack' \
         -o -name 'distutils-precedence.pth' \) \
      -exec rm -rf '{}' + \
 && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 \
          /usr/local/bin/easy_install /usr/local/bin/easy_install-3.13
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

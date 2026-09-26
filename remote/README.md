# Email MCP remote transport

A single-operator FastMCP 4 front end for the unchanged Wh1isper IMAP/SMTP engine.
See [deployment instructions](../docs/remote-oauth.md) and [design/threat model](../docs/remote-design.md).

The public `/mcp` uses OAuth bearer tokens. A local username and **Argon2id password
hash** protect the browser login/consent step. No external identity provider,
GitHub OAuth App, default password, or mail credentials are built into the image.

## Development

Python 3.13 is required. The engine and front end MUST have separate environments:
upstream requires MCP SDK v1; this module uses FastMCP 4 / SDK v2.

```sh
python3.13 -m venv .venv-remote
.venv-remote/bin/pip install --require-hashes -r remote/requirements-ci.txt
.venv-remote/bin/pip install --no-deps -e remote
cd remote
../.venv-remote/bin/python -m pytest -q
../.venv-remote/bin/ruff check src tests scripts
```

`requirements-runtime.txt` and `requirements-ci.txt` pin the tested Linux/Python 3.13
dependency closures and include hashes for the published distributions. CI and the
container build install them with pip's `--require-hashes` mode. After deliberately
upgrading dependencies in a clean environment, run `python remote/scripts/lock_installed.py`
to regenerate the pins and hashes with `uv pip compile --generate-hashes`, review the
diff, and rerun CI on both architectures.
The upstream `uv.lock` stays authoritative for the engine environment; the remote
transport remains an independently pinned project.

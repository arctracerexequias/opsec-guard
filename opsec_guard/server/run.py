"""Server management — auto-start and manual start."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import typer

app_cli = typer.Typer(help="Run the OpsecGuard monitoring server.")

SERVER_CONFIG_FILE = Path.home() / ".opsec-guard" / "server.conf"
DEFAULT_PORT = 8443


def _load_server_config() -> dict:
    if not SERVER_CONFIG_FILE.exists():
        return {}
    import json
    try:
        return json.loads(SERVER_CONFIG_FILE.read_text())
    except Exception:
        return {}


def _save_server_config(cfg: dict) -> None:
    import json
    SERVER_CONFIG_FILE.parent.mkdir(mode=0o700, exist_ok=True)
    SERVER_CONFIG_FILE.write_text(json.dumps(cfg, indent=2))


def is_port_open(host: str = "127.0.0.1", port: int = DEFAULT_PORT) -> bool:
    """Return True if something is already listening on host:port."""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except (ConnectionRefusedError, OSError):
        return False


def get_server_url() -> str:
    cfg = _load_server_config()
    host = cfg.get("host", "127.0.0.1")
    port = cfg.get("port", DEFAULT_PORT)
    scheme = "https" if cfg.get("ssl_cert") else "http"
    return f"{scheme}://{host}:{port}"


def ensure_server_running(
    port: int = DEFAULT_PORT,
    host: str = "0.0.0.0",
    ssl_cert: Optional[str] = None,
    ssl_key: Optional[str] = None,
) -> tuple[bool, str]:
    """
    Ensure the monitoring server is running.
    Returns (already_running: bool, server_url: str).
    Starts a background subprocess if not already running.
    """
    listen_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    if is_port_open(listen_host, port):
        scheme = "https" if ssl_cert else "http"
        return True, f"{scheme}://{listen_host}:{port}"

    # Build uvicorn command
    cmd = [
        sys.executable, "-m", "uvicorn",
        "opsec_guard.server.app:app",
        "--host", host,
        "--port", str(port),
        "--log-level", "warning",
    ]
    if ssl_cert and ssl_key:
        cmd += ["--ssl-certfile", ssl_cert, "--ssl-keyfile", ssl_key]

    # Persist config so get_server_url() works
    _save_server_config({
        "host": listen_host,
        "port": port,
        "ssl_cert": ssl_cert,
        "ssl_key": ssl_key,
    })

    # Start as detached background process
    log_file = Path.home() / ".opsec-guard" / "server.log"
    log_file.parent.mkdir(mode=0o700, exist_ok=True)

    with open(log_file, "a") as log:
        subprocess.Popen(
            cmd,
            stdout=log,
            stderr=log,
            start_new_session=True,  # detach from terminal
        )

    # Wait up to 5s for it to come up
    for _ in range(10):
        time.sleep(0.5)
        if is_port_open(listen_host, port):
            scheme = "https" if ssl_cert else "http"
            return False, f"{scheme}://{listen_host}:{port}"

    scheme = "https" if ssl_cert else "http"
    return False, f"{scheme}://{listen_host}:{port}"  # return URL even if not confirmed yet


@app_cli.command("start")
def start(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind host"),
    port: int = typer.Option(DEFAULT_PORT, "--port", "-p", help="Bind port"),
    ssl_cert: Optional[str] = typer.Option(None, "--cert", help="TLS certificate file"),
    ssl_key: Optional[str] = typer.Option(None, "--key", help="TLS key file"),
    background: bool = typer.Option(False, "--background", "-b", help="Run in background"),
):
    """Start the OpsecGuard monitoring server."""
    import uvicorn
    from ..utils.display import console

    if not ssl_cert:
        console.print(
            "[warn]No TLS certificate provided. Running over HTTP.[/warn]\n"
            "[dim]For HTTPS: opsec-guard server start --cert cert.pem --key key.pem\n"
            "Self-signed: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes[/dim]"
        )

    _save_server_config({"host": "127.0.0.1", "port": port, "ssl_cert": ssl_cert})

    if background:
        already, url = ensure_server_running(port, host, ssl_cert, ssl_key)
        if already:
            console.print(f"[ok]Server already running at {url}[/ok]")
        else:
            console.print(f"[ok]Server started in background: {url}[/ok]")
            console.print(f"[dim]Logs: ~/.opsec-guard/server.log[/dim]")
        return

    ssl_kwargs = {}
    if ssl_cert and ssl_key:
        ssl_kwargs = {"ssl_certfile": ssl_cert, "ssl_keyfile": ssl_key}

    console.print(f"[info]Starting server on {host}:{port}[/info]")
    uvicorn.run(
        "opsec_guard.server.app:app",
        host=host,
        port=port,
        **ssl_kwargs,
    )

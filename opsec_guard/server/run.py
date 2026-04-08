"""Server startup CLI command."""
import typer
import uvicorn

app_cli = typer.Typer(help="Run the OpsecGuard monitoring server.")


@app_cli.command("start")
def start(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind host"),
    port: int = typer.Option(8443, "--port", "-p", help="Bind port"),
    ssl_cert: str = typer.Option(None, "--cert", help="TLS certificate file"),
    ssl_key: str = typer.Option(None, "--key", help="TLS key file"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on code change (dev only)"),
):
    """Start the OpsecGuard monitoring server."""
    ssl_kwargs = {}
    if ssl_cert and ssl_key:
        ssl_kwargs = {"ssl_certfile": ssl_cert, "ssl_keyfile": ssl_key}
    elif not ssl_cert:
        import typer
        typer.echo(
            "WARNING: Running without TLS. Device reports will be unencrypted.\n"
            "For production: use --cert and --key with a valid TLS certificate.\n"
            "Self-signed: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes"
        )

    uvicorn.run(
        "opsec_guard.server.app:app",
        host=host,
        port=port,
        reload=reload,
        **ssl_kwargs,
    )

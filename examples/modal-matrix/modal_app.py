"""Deploy nullclaw Matrix gateway on Modal.

Secrets are loaded from .env via modal.Secret.from_dotenv() and injected
into config.json at container startup — they never touch the config file
on disk.

Optional Tailscale integration: set TAILSCALE_AUTHKEY in .env to join
your tailnet and SSH into the container.

Deploy:
  ./deploy.sh

Logs:
  modal app logs nullclaw-matrix
"""

import json
import os
import subprocess
import time
from pathlib import Path

import modal

example_dir = str(Path(__file__).resolve().parent)

image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("ca-certificates", "curl", "git", "openssh-server")
    .run_commands("curl -fsSL https://tailscale.com/install.sh | sh")
    .add_local_file(
        f"{example_dir}/nullclaw-linux-musl",
        "/opt/nullclaw",
    )
    .add_local_file(
        f"{example_dir}/config.matrix.json",
        "/tmp/config.matrix.json",
    )
)

app = modal.App("nullclaw-matrix")


def inject_secrets(config: dict) -> dict:
    """Patch config dict with secrets from environment variables."""
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if api_key:
        config.setdefault("models", {}).setdefault("providers", {}).setdefault("openrouter", {})
        config["models"]["providers"]["openrouter"]["api_key"] = api_key

    planner_token = os.environ.get("MATRIX_PLANNER_TOKEN", "")
    if planner_token:
        config.setdefault("channels", {}).setdefault("matrix", {}).setdefault("accounts", {})
        accounts = config["channels"]["matrix"]["accounts"]
        accounts.setdefault("planner-account", {})["access_token"] = planner_token

    builder_token = os.environ.get("MATRIX_BUILDER_TOKEN", "")
    if builder_token:
        config.setdefault("channels", {}).setdefault("matrix", {}).setdefault("accounts", {})
        accounts = config["channels"]["matrix"]["accounts"]
        accounts.setdefault("builder-account", {})["access_token"] = builder_token

    return config


def start_tailscale():
    """Start Tailscale daemon and bring up the node if TAILSCALE_AUTHKEY is set."""
    authkey = os.environ.get("TAILSCALE_AUTHKEY", "")
    if not authkey:
        return

    # Start tailscaled in userspace networking mode
    subprocess.Popen(
        ["tailscaled", "--tun=userspace-networking", "--socks5-server=localhost:1080"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    hostname = os.environ.get("TAILSCALE_HOSTNAME", "nullclaw-modal")
    subprocess.run(
        [
            "tailscale", "up",
            "--authkey", authkey,
            "--hostname", hostname,
            "--ssh",
        ],
        check=True,
    )
    print(f"Tailscale up — SSH via: ssh root@{hostname}")


@app.function(
    image=image,
    secrets=[modal.Secret.from_dotenv(path=example_dir)],
    min_containers=1,
    timeout=86400,
)
@modal.web_server(3000)
def gateway():
    # Tailscale SSH (optional)
    start_tailscale()

    # Load config and inject secrets
    with open("/tmp/config.matrix.json") as f:
        config = json.load(f)

    config = inject_secrets(config)

    # Write patched config for nullclaw
    config_dir = Path("/nullclaw-data/.nullclaw")
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.json"
    config_path.write_text(json.dumps(config, indent=2))

    # Set up workspace
    workspace = Path("/nullclaw-data/workspace")
    workspace.mkdir(parents=True, exist_ok=True)

    # Expose GITHUB_TOKEN to git via .netrc
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        netrc_path = Path("/nullclaw-data/.netrc")
        netrc_path.write_text(
            f"machine github.com\nlogin x-access-token\npassword {token}\n"
        )
        netrc_path.chmod(0o600)

    env = os.environ.copy()
    env["HOME"] = "/nullclaw-data"
    env["NULLCLAW_WORKSPACE"] = "/nullclaw-data/workspace"

    subprocess.Popen(
        ["/opt/nullclaw", "gateway", "--port", "3000", "--host", "::"],
        env=env,
    )

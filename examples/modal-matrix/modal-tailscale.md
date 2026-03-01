# Add Modal Apps to Tailscale

This example demonstrates how to integrate Modal with Tailscale (https://tailscale.com).
It outlines the steps to configure Modal containers so that they join the Tailscale network.

We use a custom entrypoint to automatically add containers to a Tailscale network (tailnet).
This configuration enables the containers to interact with one another and with
additional applications within the same tailnet.

```python
import modal

```

Install Tailscale and copy custom entrypoint script ([entrypoint.sh](https://github.com/modal-labs/modal-examples/blob/main/10_integrations/tailscale/entrypoint.sh)). The script must be
executable.

```python
image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install("curl")
    .run_commands("curl -fsSL https://tailscale.com/install.sh | sh")
    .uv_pip_install("requests==2.32.3", "PySocks==1.7.1")
    .add_local_file("./entrypoint.sh", "/root/entrypoint.sh", copy=True)
    .run_commands("chmod a+x /root/entrypoint.sh")
    .entrypoint(["/root/entrypoint.sh"])
)
app = modal.App("example-modal-tailscale", image=image)

```

Packages might not be installed locally. This catches import errors and
only attempts imports in the container.

```python
with image.imports():
    import socket

    import socks

```

Configure Python to use the SOCKS5 proxy globally.

```python
if not modal.is_local():
    socks.set_default_proxy(socks.SOCKS5, "0.0.0.0", 1080)
    socket.socket = socks.socksocket


```

Run your function adding a Tailscale secret. We suggest creating a [reusable and ephemeral key](https://tailscale.com/kb/1111/ephemeral-nodes).

```python
@app.function(
    secrets=[
        modal.Secret.from_name("tailscale-auth", required_keys=["TAILSCALE_AUTHKEY"]),
        modal.Secret.from_dict(
            {
                "ALL_PROXY": "socks5://localhost:1080/",
                "HTTP_PROXY": "http://localhost:1080/",
                "http_proxy": "http://localhost:1080/",
            }
        ),
    ],
)
def connect_to_machine():
    import requests

    # Connect to other machines in your tailnet.
    resp = requests.get("http://my-tailscale-machine:5000")
    print(resp.content)


```

Run this script with `modal run modal_tailscale.py`. You will see Tailscale logs
when the container start indicating that you were able to login successfully and
that the proxies (SOCKS5 and HTTP) have created been successfully. You will also
be able to see Modal containers in your Tailscale dashboard in the "Machines" tab.
Every new container launched will show up as a new "machine". Containers are
individually addressable using their Tailscale name or IP address.
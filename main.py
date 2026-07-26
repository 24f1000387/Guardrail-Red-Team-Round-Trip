from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import ipaddress
import socket
import requests

app = FastAPI()

# -----------------------------
# Configuration
# -----------------------------

SANDBOX_ROOT = Path(
    "/srv/agent-redteam/sandbox-d6362b7c62"
).resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

# -----------------------------
# Models
# -----------------------------

class ToolRequest(BaseModel):
    tool: str
    arguments: dict


# -----------------------------
# Helpers
# -----------------------------

def block(reason):
    return {
        "action": "block",
        "reason": reason,
        "result": None,
    }


def allow(result):
    return {
        "action": "allow",
        "reason": "ok",
        "result": result,
    }


# -----------------------------
# FILE GUARD
# -----------------------------

def read_file_guard(path_str: str):
    try:
        requested = (SANDBOX_ROOT / path_str).resolve(strict=False)

        requested.relative_to(SANDBOX_ROOT)

    except Exception:
        return block("path outside sandbox")

    if not requested.exists():
        return block("file not found")

    if not requested.is_file():
        return block("not a file")

    try:
        text = requested.read_text(errors="replace")
    except Exception:
        return block("cannot read")

    return allow(text)


# -----------------------------
# URL GUARD
# -----------------------------

def hostname_allowed(host):

    if host not in ALLOWED_HOSTS:
        return False

    return True


def ip_is_public(ip):

    addr = ipaddress.ip_address(ip)

    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_dns(host):

    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False

    for info in infos:
        ip = info[4][0]

        if not ip_is_public(ip):
            return False

    return True


def fetch_guard(url):

    try:
        parsed = urlparse(url)
    except Exception:
        return block("bad url")

    if parsed.scheme not in ("http", "https"):
        return block("bad scheme")

    if parsed.username or parsed.password:
        return block("userinfo forbidden")

    host = parsed.hostname

    if not hostname_allowed(host):
        return block("host forbidden")

    if not validate_dns(host):
        return block("private address")

    try:

        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
        )

    except Exception:
        return block("fetch failed")

    if response.is_redirect:

        location = response.headers.get("Location")

        if not location:
            return block("redirect")

        nxt = urlparse(location)

        if nxt.scheme not in ("http", "https"):
            return block("redirect")

        if nxt.username or nxt.password:
            return block("redirect")

        if nxt.hostname not in ALLOWED_HOSTS:
            return block("redirect forbidden")

        if not validate_dns(nxt.hostname):
            return block("redirect private")

        try:
            response = requests.get(
                location,
                timeout=5,
                allow_redirects=False,
            )
        except Exception:
            return block("redirect failed")

    return allow(response.text)


# -----------------------------
# Endpoint
# -----------------------------

@app.post("/check")
def check(req: ToolRequest):

    if req.tool == "read_file":
        return read_file_guard(req.arguments.get("path", ""))

    elif req.tool == "fetch_url":
        return fetch_guard(req.arguments.get("url", ""))

    return block("unknown tool")

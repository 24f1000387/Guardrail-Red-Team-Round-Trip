import os
import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# ASSIGNMENT PATHS
# ============================================================

SANDBOX = Path("/srv/agent-redteam/sandbox-d6362b7c62")
OUTSIDE = Path("/srv/agent-redteam/outside-8eedb7a4")

# Render's writable filesystem
BASE = Path(__file__).resolve().parent
DATA = BASE / ".guardrail_data"

REAL_SANDBOX = DATA / "sandbox-d6362b7c62"
REAL_OUTSIDE = DATA / "outside-8eedb7a4"

REAL_SANDBOX.mkdir(parents=True, exist_ok=True)
REAL_OUTSIDE.mkdir(parents=True, exist_ok=True)

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
TIMEOUT = 10


# ============================================================
# REQUIRED SAFE/CANARY FILES
# ============================================================

def setup_files():
    files = {
        REAL_OUTSIDE / "canary.txt":
            "AGENT_GUARDRAIL_CANARY_1c2a6d1fb68c388e83c4bb6ed8800243bb46055b",

        REAL_SANDBOX / "notes" / "report.txt":
            "SAFE_REPORT_c737e56687c592c61115c8a8",

        REAL_SANDBOX / "notes" / "looks-like-..-but-safe.txt":
            "SAFE_WEIRD_1c15f001ff96a53064b7b7d4",

        REAL_SANDBOX / "encoded" / "%2e%2e-literal.txt":
            "SAFE_ENCODED_870e1d4253182f20a8118688",
    }

    for path, text in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


setup_files()


# ============================================================
# FILE GUARDRAIL
# ============================================================

def normalize_virtual_path(value):
    """
    Normalize the requested path lexically.

    This intentionally works on the assignment's virtual path
    rather than calling resolve() on /srv, because /srv is not
    writable/available as a real sandbox on Render.
    """

    if not isinstance(value, str) or not value:
        return None

    if "\x00" in value:
        return None

    p = Path(value)

    if not p.is_absolute():
        p = SANDBOX / p

    # Convert to POSIX-style components.
    raw = p.as_posix()

    components = []

    for component in raw.split("/"):
        if component == "" or component == ".":
            continue

        if component == "..":
            if components:
                components.pop()
            else:
                # Attempt to go above filesystem root.
                return None
        else:
            components.append(component)

    return Path("/") / Path(*components)


def inside_sandbox(path):
    try:
        path.relative_to(SANDBOX)
        return True
    except ValueError:
        return False


def get_real_path(virtual_path):
    relative = virtual_path.relative_to(SANDBOX)

    real = REAL_SANDBOX.joinpath(*relative.parts)

    # Protect against symlinks in the actual writable filesystem.
    try:
        real_resolved = real.resolve(strict=False)
        sandbox_resolved = REAL_SANDBOX.resolve()

        real_resolved.relative_to(sandbox_resolved)
        return real_resolved

    except (ValueError, OSError, RuntimeError):
        return None


def guarded_read_file(user_path):
    normalized = normalize_virtual_path(user_path)

    if normalized is None:
        return False, "invalid path", None

    if not inside_sandbox(normalized):
        return False, "path outside sandbox", None

    real_path = get_real_path(normalized)

    if real_path is None:
        return False, "path outside sandbox", None

    if not real_path.is_file():
        return False, "file does not exist", None

    try:
        data = real_path.read_bytes()

        if len(data) > MAX_BYTES:
            return False, "file too large", None

        return True, "path is inside sandbox", data.decode(
            "utf-8",
            errors="replace"
        )

    except OSError:
        return False, "unable to read file", None


# ============================================================
# SSRF GUARDRAIL
# ============================================================

def public_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
        return address.is_global
    except ValueError:
        return False


def resolve_public(host):
    """
    Resolve the hostname and make sure every returned address
    is globally routable.
    """

    try:
        answers = socket.getaddrinfo(
            host,
            443,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return False

    addresses = set()

    for answer in answers:
        try:
            addresses.add(answer[4][0])
        except (IndexError, TypeError):
            pass

    if not addresses:
        return False

    return all(public_ip(ip) for ip in addresses)


def validate_url(url):
    if not isinstance(url, str) or not url:
        return False, "invalid URL"

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "malformed URL"

    # Assignment says public HTTPS URLs.
    if parsed.scheme.lower() != "https":
        return False, "only HTTPS URLs are allowed"

    if not parsed.hostname:
        return False, "missing hostname"

    hostname = parsed.hostname.lower().rstrip(".")

    # Exact allowlist. Do NOT use endswith().
    if hostname not in ALLOWED_HOSTS:
        return False, "hostname not allowed"

    # Prevent userinfo confusion.
    if parsed.username is not None:
        return False, "userinfo not allowed"

    if parsed.password is not None:
        return False, "userinfo not allowed"

    try:
        port = parsed.port
    except ValueError:
        return False, "invalid port"

    if port is not None and port != 443:
        return False, "non-standard port blocked"

    if not resolve_public(hostname):
        return False, "hostname does not resolve to a public address"

    return True, "URL allowed"


def guarded_fetch_url(url):
    current = url

    session = requests.Session()

    session.headers.update({
        "User-Agent": "guardrail-redteam/1.0",
        "Accept": "*/*",
    })

    try:
        for _ in range(MAX_REDIRECTS + 1):

            allowed, reason = validate_url(current)

            if not allowed:
                return False, reason, None

            try:
                response = session.get(
                    current,
                    timeout=TIMEOUT,
                    allow_redirects=False,
                    stream=True,
                )
            except requests.RequestException:
                return False, "network request failed", None

            # ------------------------------------------------
            # Redirect
            # ------------------------------------------------

            if response.status_code in (
                301,
                302,
                303,
                307,
                308,
            ):
                location = response.headers.get("Location")

                if not location:
                    response.close()
                    return False, "redirect without Location", None

                next_url = urljoin(current, location)

                # Validate EVERY redirect destination.
                allowed, reason = validate_url(next_url)

                response.close()

                if not allowed:
                    return False, "redirect blocked: " + reason, None

                current = next_url
                continue

            # ------------------------------------------------
            # Normal response
            # ------------------------------------------------

            data = bytearray()

            try:
                for chunk in response.iter_content(65536):
                    if chunk:
                        data.extend(chunk)

                    if len(data) > MAX_BYTES:
                        response.close()
                        return False, "response too large", None

            finally:
                response.close()

            return (
                True,
                "HTTPS host is allowed",
                data.decode("utf-8", errors="replace"),
            )

        return False, "too many redirects", None

    finally:
        session.close()


# ============================================================
# HTTP ENDPOINT
# ============================================================

@app.get("/")
def home():
    return jsonify({
        "status": "ok",
        "service": "agent-redteam-guardrail",
    })


@app.get("/health")
def health():
    return jsonify({
        "status": "healthy"
    })


@app.post("/guard")
def guard():

    # IMPORTANT:
    # Guardrail decisions are HTTP 200, including blocks.
    # The grader evaluates the JSON "action" field.
    try:

        body = request.get_json(silent=True)

        if not isinstance(body, dict):
            return jsonify({
                "action": "block",
                "reason": "invalid JSON request",
                "result": None,
            }), 200

        tool = body.get("tool")
        arguments = body.get("arguments")

        if not isinstance(arguments, dict):
            return jsonify({
                "action": "block",
                "reason": "arguments must be an object",
                "result": None,
            }), 200

        # ====================================================
        # read_file
        # ====================================================

        if tool == "read_file":

            path = arguments.get("path")

            allowed, reason, content = guarded_read_file(path)

            if not allowed:
                return jsonify({
                    "action": "block",
                    "reason": reason,
                    "result": None,
                }), 200

            return jsonify({
                "action": "allow",
                "reason": reason,
                "result": {
                    "content": content
                },
            }), 200

        # ====================================================
        # fetch_url
        # ====================================================

        if tool == "fetch_url":

            url = arguments.get("url")

            allowed, reason, content = guarded_fetch_url(url)

            if not allowed:
                return jsonify({
                    "action": "block",
                    "reason": reason,
                    "result": None,
                }), 200

            return jsonify({
                "action": "allow",
                "reason": reason,
                "result": {
                    "body": content
                },
            }), 200

        # ====================================================
        # Unknown tool
        # ====================================================

        return jsonify({
            "action": "block",
            "reason": "unknown tool",
            "result": None,
        }), 200

    except Exception as exc:

        # Never allow an application exception to become a 500.
        return jsonify({
            "action": "block",
            "reason": "guardrail error",
            "result": None,
        }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)

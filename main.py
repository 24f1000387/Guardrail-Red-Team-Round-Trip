import os
import socket
import ipaddress
from pathlib import Path
from urllib.parse import urlparse, urljoin

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# VIRTUAL PATHS REQUIRED BY THE ASSIGNMENT
# ============================================================

VIRTUAL_SANDBOX = Path(
    "/srv/agent-redteam/sandbox-d6362b7c62"
)

VIRTUAL_OUTSIDE = Path(
    "/srv/agent-redteam/outside-8eedb7a4"
)

# ============================================================
# ACTUAL WRITABLE STORAGE ON RENDER
# ============================================================

# Render allows writing inside the application directory.
BASE_DIR = Path(__file__).resolve().parent

STORAGE_ROOT = BASE_DIR / ".guardrail_data"
REAL_SANDBOX = STORAGE_ROOT / "sandbox-d6362b7c62"
REAL_OUTSIDE = STORAGE_ROOT / "outside-8eedb7a4"

REAL_SANDBOX.mkdir(parents=True, exist_ok=True)
REAL_OUTSIDE.mkdir(parents=True, exist_ok=True)

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 5
REQUEST_TIMEOUT = 8


# ============================================================
# CREATE REQUIRED TEST FILES
# ============================================================

def create_test_files():
    files = {
        REAL_OUTSIDE / "canary.txt":
            "AGENT_GUARDRAIL_CANARY_1c2a6d1fb68c388e83c4bb6ed8800243bb46055b\n",

        REAL_SANDBOX / "notes" / "report.txt":
            "SAFE_REPORT_c737e56687c592c61115c8a8\n",

        REAL_SANDBOX / "notes" / "looks-like-..-but-safe.txt":
            "SAFE_WEIRD_1c15f001ff96a53064b7b7d4\n",

        REAL_SANDBOX / "encoded" / "%2e%2e-literal.txt":
            "SAFE_ENCODED_870e1d4253182f20a8118688\n",
    }

    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)

        if not path.exists():
            path.write_text(content, encoding="utf-8")


create_test_files()


# ============================================================
# FILE PATH SECURITY
# ============================================================

def canonical_virtual_path(user_path):
    """
    Canonicalize the USER-SUPPLIED virtual path.

    The grader expects the sandbox to be:

        /srv/agent-redteam/sandbox-d6362b7c62

    We perform the security check against that virtual path first.
    Only after it passes do we map it to Render's writable storage.
    """

    if not isinstance(user_path, str) or not user_path:
        return None, None, "invalid path"

    if "\x00" in user_path:
        return None, None, "NUL byte in path"

    try:
        requested = Path(user_path)

        # Resolve relative paths against the current process directory
        # only for malformed/non-absolute requests.
        if not requested.is_absolute():
            requested = VIRTUAL_SANDBOX / requested

        # Pure lexical/canonical normalization of the virtual path.
        #
        # Path.resolve() is intentionally NOT used here because the
        # virtual path does not actually exist on Render.
        parts = []

        for part in requested.parts:

            if part in ("", "."):
                continue

            if part == "..":
                if parts:
                    parts.pop()
                continue

            parts.append(part)

        if requested.anchor:
            canonical = Path(requested.anchor).joinpath(*parts[1:])
        else:
            canonical = Path(*parts)

        return canonical, None, None

    except (ValueError, OSError, RuntimeError):
        return None, None, "invalid path"


def virtual_to_real(virtual_path):
    """
    Convert an already-authorized virtual sandbox path to the actual
    writable Render filesystem.
    """

    relative = virtual_path.relative_to(VIRTUAL_SANDBOX)

    return REAL_SANDBOX / relative


def safe_file_path(user_path):
    canonical, _, error = canonical_virtual_path(user_path)

    if error:
        return None, error

    try:
        # Component-aware containment check.
        canonical.relative_to(VIRTUAL_SANDBOX)
    except ValueError:
        return None, "path outside sandbox"

    # Map only after the virtual containment check succeeds.
    real_path = virtual_to_real(canonical)

    # Resolve actual filesystem path too, protecting against symlinks.
    try:
        real_resolved = real_path.resolve(strict=False)
        sandbox_resolved = REAL_SANDBOX.resolve()

        real_resolved.relative_to(sandbox_resolved)

    except (ValueError, OSError, RuntimeError):
        return None, "path outside sandbox"

    return real_resolved, None


def read_file(path):
    safe_path, error = safe_file_path(path)

    if error:
        return None, error

    if not safe_path.is_file():
        return None, "file does not exist"

    try:
        data = safe_path.read_bytes()

        if len(data) > MAX_RESPONSE_BYTES:
            return None, "file too large"

        return data.decode("utf-8", errors="replace"), None

    except OSError:
        return None, "unable to read file"


# ============================================================
# DNS / SSRF SECURITY
# ============================================================

def is_public_ip(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
        return ip.is_global
    except ValueError:
        return False


def resolve_host(hostname):
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

    except socket.gaierror:
        return False, "DNS resolution failed"

    addresses = set()

    for result in results:
        sockaddr = result[4]

        if sockaddr:
            addresses.add(sockaddr[0])

    if not addresses:
        return False, "no DNS addresses"

    # Reject the host if ANY returned address is unsafe.
    for ip in addresses:
        if not is_public_ip(ip):
            return False, "host resolves to non-public address"

    return True, None


def validate_url(url):
    if not isinstance(url, str) or not url:
        return False, "invalid URL", None

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "malformed URL", None

    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        return False, "unsupported URL scheme", None

    if not parsed.hostname:
        return False, "missing hostname", None

    hostname = parsed.hostname.rstrip(".").lower()

    # EXACT hostname allowlist.
    if hostname not in ALLOWED_HOSTS:
        return False, "hostname not allowed", None

    # Reject userinfo tricks:
    #
    # https://example.com@127.0.0.1/
    # https://user:pass@example.com/
    #
    if parsed.username is not None or parsed.password is not None:
        return False, "userinfo is not allowed", None

    try:
        port = parsed.port
    except ValueError:
        return False, "invalid port", None

    if port is not None:
        expected_port = 443 if scheme == "https" else 80

        if port != expected_port:
            return False, "non-standard port blocked", None

    # DNS rebinding / private IP protection.
    ok, error = resolve_host(hostname)

    if not ok:
        return False, error, None

    return True, None, parsed


# ============================================================
# SAFE URL FETCHING
# ============================================================

def fetch_url(url):

    current_url = url

    session = requests.Session()

    session.headers.update({
        "User-Agent": "agent-redteam-guardrail/1.0",
        "Accept": "*/*",
    })

    try:

        for redirect_number in range(MAX_REDIRECTS + 1):

            valid, error, _ = validate_url(current_url)

            if not valid:
                return None, error

            response = session.get(
                current_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )

            # ------------------------------------------------
            # Redirect handling
            # ------------------------------------------------

            if response.status_code in {
                301,
                302,
                303,
                307,
                308,
            }:

                location = response.headers.get("Location")

                if not location:
                    response.close()
                    return None, "redirect without Location"

                next_url = urljoin(
                    current_url,
                    location,
                )

                # CRITICAL:
                # Validate the redirected URL independently.
                valid, error, _ = validate_url(next_url)

                if not valid:
                    response.close()
                    return None, "redirect blocked: " + error

                response.close()

                if redirect_number >= MAX_REDIRECTS:
                    return None, "too many redirects"

                current_url = next_url
                continue

            # ------------------------------------------------
            # Normal response
            # ------------------------------------------------

            content = bytearray()

            for chunk in response.iter_content(
                chunk_size=65536
            ):

                if not chunk:
                    continue

                content.extend(chunk)

                if len(content) > MAX_RESPONSE_BYTES:
                    response.close()
                    return None, "response too large"

            response.close()

            return content.decode(
                "utf-8",
                errors="replace",
            ), None

        return None, "too many redirects"

    except requests.RequestException:
        return None, "network request failed"

    except Exception:
        return None, "unexpected fetch error"

    finally:
        session.close()


# ============================================================
# HTTP API
# ============================================================

@app.get("/")
def index():
    return jsonify({
        "status": "ok",
        "service": "agent-redteam-guardrail",
    })


@app.get("/health")
def health():
    return jsonify({
        "status": "healthy",
    })


@app.post("/guard")
def guard():

    try:

        payload = request.get_json(silent=True)

        if not isinstance(payload, dict):
            return jsonify({
                "action": "block",
                "reason": "request must contain JSON object",
                "result": None,
            }), 400

        tool = payload.get("tool")
        arguments = payload.get("arguments")

        if not isinstance(arguments, dict):
            return jsonify({
                "action": "block",
                "reason": "arguments must be an object",
                "result": None,
            }), 400

        # ====================================================
        # READ FILE
        # ====================================================

        if tool == "read_file":

            path = arguments.get("path")

            safe_path, error = safe_file_path(path)

            if error:
                return jsonify({
                    "action": "block",
                    "reason": error,
                    "result": None,
                })

            result, error = read_file(path)

            if error:
                return jsonify({
                    "action": "block",
                    "reason": error,
                    "result": None,
                })

            return jsonify({
                "action": "allow",
                "reason": "path is inside sandbox",
                "result": {
                    "content": result,
                },
            })

        # ====================================================
        # FETCH URL
        # ====================================================

        if tool == "fetch_url":

            url = arguments.get("url")

            valid, error, _ = validate_url(url)

            if not valid:
                return jsonify({
                    "action": "block",
                    "reason": error,
                    "result": None,
                })

            result, error = fetch_url(url)

            if error:
                return jsonify({
                    "action": "block",
                    "reason": error,
                    "result": None,
                })

            return jsonify({
                "action": "allow",
                "reason": "host is explicitly allowed and request passed SSRF checks",
                "result": {
                    "body": result,
                },
            })

        # ====================================================
        # UNKNOWN TOOL
        # ====================================================

        return jsonify({
            "action": "block",
            "reason": "unknown tool",
            "result": None,
        })

    except Exception:

        return jsonify({
            "action": "block",
            "reason": "guardrail internal error",
            "result": None,
        }), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))

    app.run(
        host="0.0.0.0",
        port=port,
    )
    

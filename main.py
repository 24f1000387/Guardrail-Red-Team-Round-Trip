import os
import socket
import ipaddress
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse, urljoin, unquote

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# ============================================================
# VIRTUAL PATHS FROM THE ASSIGNMENT
# ============================================================

SANDBOX_VIRTUAL = "/srv/agent-redteam/sandbox-d6362b7c62"
OUTSIDE_VIRTUAL = "/srv/agent-redteam/outside-8eedb7a4"

# ============================================================
# ACTUAL WRITABLE RENDER STORAGE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / ".guardrail_data"

REAL_SANDBOX = DATA_DIR / "sandbox-d6362b7c62"
REAL_OUTSIDE = DATA_DIR / "outside-8eedb7a4"

REAL_SANDBOX.mkdir(parents=True, exist_ok=True)
REAL_OUTSIDE.mkdir(parents=True, exist_ok=True)

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 10
MAX_REDIRECTS = 5


# ============================================================
# CREATE THE ASSIGNMENT'S SAFE FILES
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

    for filename, content in files.items():
        filename.parent.mkdir(parents=True, exist_ok=True)
        filename.write_text(content, encoding="utf-8")


setup_files()


# ============================================================
# PATH NORMALIZATION
# ============================================================

def normalize_path(raw):
    if not isinstance(raw, str) or raw == "":
        return None

    if "\x00" in raw:
        return None

    # Backslashes are path separators on Windows, but this server
    # is Linux. Treating them as separators as well makes the
    # boundary stricter against Windows-style traversal probes.
    raw = raw.replace("\\", "/")

    # IMPORTANT:
    # Percent encoding is NOT decoded here.
    #
    # Therefore:
    #   %2e%2e-literal.txt
    #
    # remains a literal filename, as required by the safe control.

    if not raw.startswith("/"):
        raw = SANDBOX_VIRTUAL.rstrip("/") + "/" + raw

    parts = []

    for part in raw.split("/"):
        if part == "" or part == ".":
            continue

        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue

        parts.append(part)

    normalized = "/" + "/".join(parts)

    return normalized


def path_is_inside(normalized):
    if normalized == SANDBOX_VIRTUAL:
        return True

    prefix = SANDBOX_VIRTUAL.rstrip("/") + "/"

    return normalized.startswith(prefix)


def virtual_to_real(normalized):
    if not path_is_inside(normalized):
        return None

    relative = normalized[len(SANDBOX_VIRTUAL):].lstrip("/")

    if relative == "":
        real = REAL_SANDBOX
    else:
        real = REAL_SANDBOX.joinpath(*relative.split("/"))

    # Protect against symlinks.
    try:
        resolved = real.resolve(strict=False)
        sandbox = REAL_SANDBOX.resolve()

        resolved.relative_to(sandbox)

        return resolved

    except (OSError, RuntimeError, ValueError):
        return None


def read_guarded_file(raw_path):

    normalized = normalize_path(raw_path)

    if normalized is None:
        return False, "invalid path", None

    if not path_is_inside(normalized):
        return False, "path outside sandbox", None

    real_path = virtual_to_real(normalized)

    if real_path is None:
        return False, "path outside sandbox", None

    if not real_path.is_file():
        return False, "file does not exist", None

    try:
        data = real_path.read_bytes()

        if len(data) > MAX_BYTES:
            return False, "file too large", None

        return (
            True,
            "path is inside sandbox",
            data.decode("utf-8", errors="replace"),
        )

    except OSError:
        return False, "unable to read file", None


# ============================================================
# URL SECURITY
# ============================================================

def is_public_ip(value):
    try:
        ip = ipaddress.ip_address(value)

        # Explicitly reject common unsafe classes.
        if ip.is_loopback:
            return False

        if ip.is_private:
            return False

        if ip.is_link_local:
            return False

        if ip.is_reserved:
            return False

        if ip.is_multicast:
            return False

        if ip.is_unspecified:
            return False

        return ip.is_global

    except ValueError:
        return False


def host_has_public_dns(host):
    try:
        answers = socket.getaddrinfo(
            host,
            443,
            type=socket.SOCK_STREAM,
        )
    except (socket.gaierror, OSError):
        return False

    addresses = set()

    for answer in answers:
        try:
            addresses.add(answer[4][0])
        except (IndexError, TypeError):
            pass

    if not addresses:
        return False

    return all(is_public_ip(x) for x in addresses)


def validate_https_url(url):

    if not isinstance(url, str) or not url:
        return False, "invalid URL"

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "malformed URL"

    # Assignment requires public HTTPS URLs.
    if parsed.scheme.lower() != "https":
        return False, "only HTTPS URLs are accepted"

    hostname = parsed.hostname

    if not hostname:
        return False, "missing hostname"

    hostname = hostname.rstrip(".").lower()

    # Exact host matching.
    if hostname not in ALLOWED_HOSTS:
        return False, "hostname not allowed"

    # Reject userinfo confusion.
    if parsed.username is not None:
        return False, "userinfo not allowed"

    if parsed.password is not None:
        return False, "userinfo not allowed"

    # Only normal HTTPS port.
    try:
        port = parsed.port
    except ValueError:
        return False, "invalid port"

    if port is not None and port != 443:
        return False, "non-standard port blocked"

    # Check DNS before connection.
    return True, "HTTPS host is allowed"


# ============================================================
# URL FETCH
# ============================================================

def fetch_guarded_url(url):

    current = url

    session = requests.Session()

    session.headers.update({
        "User-Agent": "agent-redteam-guardrail/1.0",
        "Accept": "*/*",
    })

    try:

        for redirect_count in range(MAX_REDIRECTS + 1):

            allowed, reason = validate_https_url(current)

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
                    return False, "redirect without Location", None

                next_url = urljoin(current, location)

                # Validate the redirect destination before
                # making another request.
                allowed, reason = validate_https_url(next_url)

                response.close()

                if not allowed:
                    return False, "redirect blocked: " + reason, None

                if redirect_count >= MAX_REDIRECTS:
                    return False, "too many redirects", None

                current = next_url
                continue

            # ------------------------------------------------
            # Normal response
            # ------------------------------------------------

            data = bytearray()

            try:
                for chunk in response.iter_content(chunk_size=65536):

                    if chunk:
                        data.extend(chunk)

                    if len(data) > MAX_BYTES:
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
# RESPONSE HELPERS
# ============================================================

def decision(action, reason, result=None):
    """
    Every guardrail decision is HTTP 200.

    This is important because the grader distinguishes:
      HTTP failure
    from:
      {"action":"block"}
    """

    return jsonify({
        "action": action,
        "reason": str(reason)[:300],
        "result": result,
    }), 200


# ============================================================
# HTTP API
# ============================================================

@app.route("/", methods=["GET", "POST"])
@app.route("/guard", methods=["POST"])
def guard():

    if request.method == "GET":
        return jsonify({
            "status": "ok",
            "service": "agent-redteam-guardrail",
        })

    try:

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return decision("block", "invalid JSON request", None)

        tool = payload.get("tool")
        arguments = payload.get("arguments")

        if not isinstance(arguments, dict):
            return decision("block", "arguments must be an object", None)

        if tool == "read_file":
            allowed, reason, content = read_guarded_file(
                arguments.get("path")
            )

            if not allowed:
                return decision("block", reason, None)

            return decision(
                "allow",
                reason,
                {"content": content},
            )

        if tool == "fetch_url":
            allowed, reason, content = fetch_guarded_url(
                arguments.get("url")
            )

            if not allowed:
                return decision("block", reason, None)

            return decision(
                "allow",
                reason,
                {"body": content},
            )

        return decision("block", "unknown tool", None)

    except Exception:
        return decision("block", "guardrail error", None)


@app.get("/health")
def health():
    return jsonify({
        "status": "healthy",
    })


# The POST / and POST /guard routes share the same guardrail handler.
# The grader submits the endpoint URL directly, so POST / must be supported.

    try:

        payload = request.get_json(silent=True)

        if not isinstance(payload, dict):
            return decision(
                "block",
                "invalid JSON request",
            )

        tool = payload.get("tool")
        arguments = payload.get("arguments")

        if not isinstance(arguments, dict):
            return decision(
                "block",
                "arguments must be an object",
            )

        # ====================================================
        # read_file
        # ====================================================

        if tool == "read_file":

            allowed, reason, content = read_guarded_file(
                arguments.get("path")
            )

            if not allowed:
                return decision(
                    "block",
                    reason,
                    None,
                )

            return decision(
                "allow",
                reason,
                {
                    "content": content
                },
            )

        # ====================================================
        # fetch_url
        # ====================================================

        if tool == "fetch_url":

            allowed, reason, content = fetch_guarded_url(
                arguments.get("url")
            )

            if not allowed:
                return decision(
                    "block",
                    reason,
                    None,
                )

            return decision(
                "allow",
                reason,
                {
                    "body": content
                },
            )

        # ====================================================
        # Unknown tool
        # ====================================================

        return decision(
            "block",
            "unknown tool",
            None,
        )

    except Exception:
        # Never leak internal exceptions and never generate 500.
        return decision(
            "block",
            "guardrail error",
            None,
        )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))

    app.run(
        host="0.0.0.0",
        port=port,
    )

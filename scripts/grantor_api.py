#!/usr/bin/env python3
"""Small HTTP client for Grantor. Credentials never become command arguments."""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class APIError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A redirect must never transmit the caller's credential to another host.
        return None


def redact(value):
    if isinstance(value, list):
        return [redact(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    sensitive = {"token", "password", "secret", "client_secret", "private_key", "csrf_token",
                 "share_url", "one_time_url", "url", "link", "session_token"}
    for key, item in value.items():
        if key.lower() in sensitive or (key.lower() == "api_key" and isinstance(item, str)):
            result[key] = "[redacted]"
        else:
            result[key] = redact(item)
    return result


class Client:
    def __init__(self, base_url, token, timeout=30, allow_local_http=False):
        parsed = urllib.parse.urlsplit(base_url)
        local = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise APIError("invalid API base URL")
        if parsed.scheme != "https" and not (allow_local_http and local and parsed.scheme == "http"):
            raise APIError("HTTPS is required; local HTTP is opt-in for loopback tests only")
        if parsed.path not in {"", "/"}:
            raise APIError("API base URL must not contain a path")
        if not token or any(char.isspace() for char in token):
            raise APIError("API token is missing or malformed")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, body=None):
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/api/v1/"):
            raise APIError("request path must stay within /api/v1/")
        private = {"token", "api_key", "password", "secret", "authorization"}
        if any(key.lower() in private for key, _ in urllib.parse.parse_qsl(parsed.query)):
            raise APIError("credentials are not allowed in URL parameters")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise APIError("unsupported HTTP method")
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers={"Authorization": "Bearer " + self.token,
                                              "Accept": "application/json", "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                payload = response.read(4 * 1024 * 1024 + 1)
                if len(payload) > 4 * 1024 * 1024:
                    raise APIError("API response exceeds the client limit")
                return {} if not payload else json.loads(payload)
        except urllib.error.HTTPError as error:
            # Do not include redirect URLs, headers, cookies or arbitrary error
            # bodies in CLI output. Failed mutations are never retried here.
            raise APIError(f"API returned HTTP {error.code}; no automatic retry") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise APIError("request failed; mutation outcome may be unknown, inspect its receipt before retrying") from None
        except (ValueError, UnicodeError):
            raise APIError("API returned an invalid JSON response") from None

    def wait(self, operation_id, timeout=180, interval=1):
        try:
            uuid.UUID(operation_id)
        except ValueError:
            raise APIError("operation ID must be a UUID") from None
        deadline = time.monotonic() + timeout
        while True:
            operation = self.request("GET", f"/api/v1/operations/{operation_id}")
            status = operation.get("status")
            if status == "success":
                return operation
            if status in {"failed", "partial", "cancelled", "rejected", "expired"}:
                raise APIError(f"operation ended with status {status}")
            if time.monotonic() >= deadline:
                raise APIError("operation wait timed out; operation may still be running")
            time.sleep(interval)


def load_token(token_ref):
    if token_ref:
        try:
            return subprocess.check_output(["op", "read", token_ref], text=True,
                                           stderr=subprocess.DEVNULL, timeout=30).strip()
        except (OSError, subprocess.SubprocessError):
            raise APIError("cannot read the configured 1Password token reference") from None
    return os.environ.get("GRANTOR_API_TOKEN", "").strip()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("GRANTOR_API_URL", "https://grantor.example.com"))
    parser.add_argument("--token-ref", default=os.environ.get("GRANTOR_API_TOKEN_REF"))
    parser.add_argument("--allow-local-http", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("whoami")
    request = sub.add_parser("request")
    request.add_argument("method", choices=["GET", "POST", "PUT", "PATCH", "DELETE"])
    request.add_argument("path")
    request.add_argument("--data-stdin", action="store_true", help="read JSON from stdin, including secret-bearing bodies")
    wait = sub.add_parser("wait")
    wait.add_argument("operation_id")
    wait.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    try:
        client = Client(args.url, load_token(args.token_ref), allow_local_http=args.allow_local_http)
        if args.command == "whoami":
            result = client.request("GET", "/api/v1/me")
        elif args.command == "wait":
            if args.timeout < 1 or args.timeout > 3600:
                raise APIError("wait timeout must be between 1 and 3600 seconds")
            result = client.wait(args.operation_id, args.timeout)
        else:
            body = None
            if args.data_stdin:
                raw = sys.stdin.read(1024 * 1024 + 1)
                if len(raw.encode()) > 1024 * 1024:
                    raise APIError("request body exceeds 1 MiB")
                try:
                    body = json.loads(raw)
                except ValueError:
                    raise APIError("stdin must contain one JSON document") from None
            result = client.request(args.method, args.path, body)
        print(json.dumps(redact(result), ensure_ascii=False, indent=2))
        return 0
    except APIError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

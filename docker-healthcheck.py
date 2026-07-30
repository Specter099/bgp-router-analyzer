#!/usr/bin/env python3
"""Container healthcheck.

/health requires authentication whenever BGP_ANALYZER_API_KEY is set, so a
plain unauthenticated GET would fail closed and mark a healthy container
unhealthy. Send the key when one is configured.

Uses only the standard library so the runtime image needs no curl/wget.

Exit codes: 0 = healthy, 1 = unhealthy (per Docker's HEALTHCHECK contract).
"""

import os
import sys
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 4


def main() -> int:
    host = os.environ.get("BGP_HEALTHCHECK_HOST", "127.0.0.1")
    port = os.environ.get("BGP_HEALTHCHECK_PORT", "8000")
    scheme = "https" if os.environ.get("BGP_HEALTHCHECK_TLS") else "http"

    request = urllib.request.Request(f"{scheme}://{host}:{port}/health")
    api_key = os.environ.get("BGP_ANALYZER_API_KEY")
    if api_key:
        request.add_header("X-API-Key", api_key)

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                print(f"unhealthy: HTTP {response.status}", file=sys.stderr)
                return 1
    except urllib.error.HTTPError as exc:
        # A 403 here means the server is up but the healthcheck key is wrong —
        # worth distinguishing in logs from a connection failure.
        print(f"unhealthy: HTTP {exc.code} (check BGP_ANALYZER_API_KEY)", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"unhealthy: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

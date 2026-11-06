"""Check the NetBridge network service already running on port 5055.

Run this while the main app is running. It does not start a second server.
"""
import json
from urllib.error import URLError
from urllib.request import urlopen


HEALTH_URL = "http://127.0.0.1:5055/health"


if __name__ == "__main__":
    try:
        with urlopen(HEALTH_URL, timeout=3) as response:
            payload = json.loads(response.read().decode("utf-8"))
            print(f"HTTP status: {response.status}")
            print(json.dumps(payload, indent=2))
            if response.status != 200 or payload.get("status") != "running":
                raise SystemExit("NetBridge network service did not report running.")
            print("NetBridge network service health check passed.")
    except (OSError, URLError, ValueError) as error:
        raise SystemExit(
            "Could not reach the NetBridge service at port 5055. "
            "Start app.py first, then run this check. "
            f"Details: {error}"
        )

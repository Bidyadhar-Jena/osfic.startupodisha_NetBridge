from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import json


HOST = "0.0.0.0"
PORT = 5055


class NetBridgeHandler(BaseHTTPRequestHandler):

    def send_json(self, status_code, data):
        response = json.dumps(data).encode("utf-8")

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self):
        print("NetBridge received request:", repr(self.path))
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            self.wfile.write(
            b'{"service":"NetBridge Network Service",'
            b'"status":"running",'
            b'"mode":"local_network_test"}'
        )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format_string, *args):
        print(f"[NetBridge Network] {args[0]}")


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_network_service():
    server = ReusableThreadingHTTPServer(
        (HOST, PORT),
        NetBridgeHandler
    )

    print(
    f"[NetBridge Network] Listening on "
    f"http://0.0.0.0:{PORT}"
)

    server.serve_forever()


def start_network_service_background():
    thread = Thread(
        target=start_network_service,
        name="NetBridgeNetworkService",
        daemon=True
    )
    thread.start()
    return thread
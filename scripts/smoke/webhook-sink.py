"""Webhook sink: prints each POST body as one JSON line to stdout."""
import http.server
import sys


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        print("EVENT\t" + body.replace("\n", " "), flush=True)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        sys.stderr.write("req: %s\n" % (args,))


http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

#!/usr/bin/env python3

"""
PlutoSDR live mirror reader
Serves runtime JSONL files to dashboard
"""

from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import os


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

RUNTIME_DIR = os.path.join(
    BASE_DIR,
    "runtime"
)


class LiveHandler(SimpleHTTPRequestHandler):

    def do_GET(self):

        if self.path == "/sweep":

            path = os.path.join(
                RUNTIME_DIR,
                "sweep_live.jsonl"
            )

            try:

                with open(
                    path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as f:

                    data = f.read()

            except FileNotFoundError:

                data = ""


            payload = data.encode(
                "utf-8"
            )

            self.send_response(200)

            self.send_header(
                "Content-Type",
                "application/json"
            )

            self.send_header(
                "Content-Length",
                len(payload)
            )

            self.send_header(
                "Access-Control-Allow-Origin",
                "*"
            )

            self.end_headers()

            self.wfile.write(
                payload
            )

            return


        super().do_GET()



if __name__ == "__main__":

    os.chdir(BASE_DIR)

    server = ThreadingHTTPServer(
        ("127.0.0.1",8080),
        LiveHandler
    )

    print(
        "Live reader running:"
    )

    print(
        "http://127.0.0.1:8080"
    )

    server.serve_forever()
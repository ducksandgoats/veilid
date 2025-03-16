import asyncio
import os
import signal
import sys
from http.server import BaseHTTPRequestHandler
from veilid.json_api import json_api_connect_ipc
from veilid.types import TypedKey, ValueSubkey
import socketserver
import argparse
import mimetypes
import urllib.parse

import hashlib
import diskcache as dc

# Initialize the cache (stored on disk)
cache = dc.Cache("./proxy_cache")  # Change the path if needed

def get_cache_key(dht_key, path, query):
    """Generate a unique cache key based on the request path and query."""
    cache_key = hashlib.sha256(f"{dht_key}?{path}?{query}".encode()).hexdigest()
    return cache_key

def cache_response(dht_key, path, query, response_bytes, expiration=3600):
    """Store the raw response in cache with a defined expiration time."""
    cache_key = get_cache_key(dht_key, path, query)
    cache.set(cache_key, response_bytes, expire=expiration)  # Store as raw bytes

def get_cached_response(dht_key, path, query):
    """Retrieve cached response as raw bytes if available."""
    cache_key = get_cache_key(dht_key, path, query)
    cached_value = cache.get(cache_key, None)
    
    # Ensure we return bytes, not hex
    if isinstance(cached_value, str) and cached_value.startswith("0x"):
        return bytes.fromhex(cached_value[2:])
    
    return cached_value



# IPC Path for Veilid
IPC_PATH = os.getenv("VEILID_SERVER_IPC")
if IPC_PATH is None:
    if os.name == "nt":
        IPC_PATH = "\\\\.\\PIPE\\veilid-server\\0"
    elif os.name == "posix":
        if 'linux' in os.uname().sysname.lower():
            IPC_PATH = "/var/db/veilid-server/ipc/0"
        elif 'darwin' in os.uname().sysname.lower():
            IPC_PATH = os.path.expanduser(f"~/Library/Application Support/org.Veilid.Veilid/ipc/0")
        else:
            raise OSError("Unsupported POSIX operating system")
    else:
        raise OSError("Unsupported operating system")
proxy_server = None

parser = argparse.ArgumentParser(
    description="Request web content from a Veilid server via DHT record."
)
parser.add_argument(
    "--port",
    type=int,
    default=9990,
    help="Port to run the proxy server on (default: 9990)",
)
args = parser.parse_args()


def handle_exit(signum, frame):
    """Cleans up processes before exiting."""
    print("\n[Client] Shutting down...")
    if proxy_server:
        proxy_server.server_close()
        print("[Proxy] Proxy server stopped.")
    os._exit(0)


class VeilidProxyHandler(BaseHTTPRequestHandler):
    """Handles incoming browser requests and routes them through Veilid."""

    def determine_content_type(self, path):
        """Determine the content type based on file extension"""
        content_type, _ = mimetypes.guess_type(path)
        if content_type is None:
            # Default to text/html for unknown types
            content_type = "text/html"
        return content_type

    def log_request(self, code="-", size="-"):
        """Customize request logging"""
        print(f"[Proxy] {self.command} {self.path} → {code}")

    def decode_response(self, response_bytes, path):
        response_str = response_bytes.decode("utf-8")
        if response_str.startswith("{") and response_str.endswith("}"):
            # This may be a structured response
            import ast

            response_dict = ast.literal_eval(response_str)

            status = response_dict.get("status", 200)
            headers = response_dict.get("headers", {})
            content = response_dict.get("content", b"")

            # Convert hex string back to bytes if needed
            if isinstance(content, str) and content.startswith("0x"):
                content = bytes.fromhex(content[2:])
            elif isinstance(content, str):
                content = content.encode("utf-8")

            # Send the structured response
            content_type = headers.get(
                "Content-Type", self.determine_content_type(path)
            )
            self.send_veilid_response(content, content_type)
            return

    def send_veilid_response(self, response_bytes, content_type=None):
        """Send response from Veilid back to the browser"""
        try:
            self.send_response(200)

            # Use provided content type or guess based on path
            if content_type is None:
                content_type = self.determine_content_type(self.path)

            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
        except Exception as e:
            print(f"[Proxy] Error sending response: {e}")

    def send_error_response(self, status_code, message):
        """Send an error response back to the browser"""
        try:
            self.send_response(status_code)
            self.send_header("Content-type", "text/html")
            error_content = f"<html><body><h1>Error {status_code}</h1><p>{message}</p></body></html>"
            error_bytes = error_content.encode("utf-8")
            self.send_header("Content-Length", str(len(error_bytes)))
            self.end_headers()
            self.wfile.write(error_bytes)
        except Exception as e:
            print(f"[Proxy] Error sending error response: {e}")

    def do_GET(self):
        """Handle HTTP GET requests"""
        asyncio.run(self.handle_request())

    def do_HEAD(self):
        """Handle HTTP HEAD requests"""
        asyncio.run(self.handle_request(head_only=True))

    def do_POST(self):
        """Handle HTTP POST requests"""
        # Read the request body
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else None
        asyncio.run(self.handle_request(body=post_data))

    async def veilid_callback(self, update):
        """Handle Veilid callbacks"""
        print(
            f"🔔 Veilid Update: {update.kind if hasattr(update, 'kind') else str(update)[:100]}"
        )

    async def handle_request(self, head_only=False, body=None):
        """Handle all types of HTTP requests through Veilid"""
        dht_key = self.headers.get("X-Iden", "")
        if dht_key == "":
            self.send_error_response(400, error_msg = f"Header must have the X-Iden key with the DHT key as the value")
            return

        # Parse the URL to extract path and query parameters
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = parsed_url.query

        # Default to index.html if path is root
        if path == "/":
            path = "/index.html"

        cached_response = get_cached_response(dht_key, path, query)
        if cached_response:
            print(f"[Cache] Serving cached response for {dht_key}?{path}?{query}")
            self.decode_response(cached_response, path)
            return  # Serve cached response and exit

        # Prepare the full request including headers
        request_data = {
            "method": self.command,
            "path": path,
            "query": query,
            "headers": dict(self.headers),
            "head_only": head_only,
        }

        # Add body data for POST/PUT requests
        if body:
            request_data["body"] = (
                body.hex()
            )  # Convert binary data to hex string for transport

        # Convert the request data to JSON and then to bytes
        request_bytes = str(request_data).encode()

        try:
            # Connect to Veilid
            api = await json_api_connect_ipc(IPC_PATH, self.veilid_callback)
            async with await api.new_routing_context() as rc:
                print(f"[Proxy] Opening DHT record: {dht_key}")
                await rc.open_dht_record(TypedKey(dht_key))

                # Get the route blob
                result = await rc.get_dht_value(
                    TypedKey(dht_key), ValueSubkey(0), force_refresh=True
                )
                if not result:
                    error_msg = f"Could not find route blob in DHT key {dht_key}"
                    print(f"❌ {error_msg}")
                    self.send_error_response(404, error_msg)
                    return

                # Import the route and talk to the server
                route_blob = result.data
                server_route_id = await api.import_remote_private_route(route_blob)
                print(f"✅ Imported server route: {server_route_id}")

                try:
                    # Make the request through Veilid
                    print(f"📡 Requesting {path} via Veilid...")
                    response_bytes = await rc.app_call(server_route_id, request_bytes)

                    # Cache the response before sending
                    cache_response(dht_key, path, query, response_bytes, expiration=3600)  # Cache for 1 hour
                    # Try to parse the response as a dictionary
                    try:
                        response = self.decode_response(response_bytes, path)
                        return response
                    except Exception:
                        # Not a structured response, treat as raw data
                        pass

                    # Send the raw response
                    self.send_veilid_response(response_bytes)

                except Exception as e:
                    error_msg = f"Veilid request failed: {str(e)}"
                    print(f"❌ {error_msg}")
                    self.send_error_response(500, error_msg)

        except Exception as e:
            error_msg = f"Failed to connect to Veilid: {str(e)}"
            print(f"❌ {error_msg}")
            self.send_error_response(500, error_msg)


def start_local_proxy(port):
    """Starts a local HTTP proxy that routes requests through Veilid."""
    global proxy_server

    # Initialize mime types
    mimetypes.init()

    # Set up signal handlers
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # Create and start the proxy server
    try:
        proxy_server = socketserver.TCPServer(("0.0.0.0", port), VeilidProxyHandler)
        print(f"[Client] Local proxy server running at http://localhost:{port}")
        print("[Client] Press Ctrl+C to exit")
        proxy_server.serve_forever()
    except KeyboardInterrupt:
        handle_exit(None, None)
    except Exception as e:
        print(f"[Client] Error starting proxy server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    start_local_proxy(args.port)

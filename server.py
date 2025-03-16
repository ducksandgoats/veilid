import asyncio
import os
import signal
import sys
import json
import urllib.parse
import mimetypes
from veilid.json_api import json_api_connect_ipc
from veilid.types import ValueSubkey, TypedKey, DHTSchema
import threading
import argparse
import os

# IPC Path for Veilid

WEB_ROOT = "./web_pages"  # Directory to serve HTML and other web assets

SERVER_API = None
CURRENT_ROUTE_ID = None
CURRENT_ROUTE_BLOB = None
CURRENT_RECORD_KEY = None


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


parser = argparse.ArgumentParser(description="Run a web server over Veilid.")
parser.add_argument(
    "--web-root",
    type=str,
    default="./web_pages",
    help="Directory to serve web files from",
)
parser.add_argument(
    "--dht-key", type=str, help="Use an existing DHT key instead of creating a new one"
)
args = parser.parse_args()


def handle_exit(signum, frame):
    """Cleans up processes before exiting."""
    print("\n[Server] Shutting down...")
    os._exit(0)


async def veilid_callback(update):
    """Handles incoming app calls for webpage requests."""
    global CURRENT_ROUTE_ID, SERVER_API

    if getattr(update, "kind", None) == "RouteChange":
        dead_routes = getattr(update.detail, "dead_routes", [])
        if CURRENT_ROUTE_ID in dead_routes:
            print("[Server] Our route expired! Re-creating now.")
            await recreate_server_route()

    if getattr(update, "kind", None) == "AppCall" and update.detail:
        await handle_web_request(update.detail)


async def recreate_server_route():
    """Re-creates the server's private route and updates DHT."""
    global SERVER_API, CURRENT_ROUTE_ID, CURRENT_ROUTE_BLOB, CURRENT_RECORD_KEY

    async with await SERVER_API.new_routing_context() as rc:
        route_id, route_blob = await SERVER_API.new_private_route()
        CURRENT_ROUTE_ID = str(route_id)
        CURRENT_ROUTE_BLOB = route_blob

        await rc.open_dht_record(CURRENT_RECORD_KEY)
        await rc.set_dht_value(CURRENT_RECORD_KEY, ValueSubkey(0), route_blob)

    print(f"[Server] Replaced old route with new route: {CURRENT_ROUTE_ID}")


def determine_content_type(path):
    """Determine the content type based on file extension"""
    content_type, _ = mimetypes.guess_type(path)
    if content_type is None:
        # Default to text/html for unknown types
        content_type = "text/html"
    return content_type


async def handle_web_request(call):
    """Processes incoming requests for web pages and serves responses."""
    global WEB_ROOT

    try:
        # Try to parse the request data
        request_data = call.message.decode("utf-8")

        # Check if it's a structured request
        try:
            import ast

            request = ast.literal_eval(request_data)

            method = request.get("method", "GET")
            path = request.get("path", "/").strip("/") or "index.html"
            query = request.get("query", "")
            headers = request.get("headers", {})
            head_only = request.get("head_only", False)
            body = None

            if "body" in request and request["body"]:
                if isinstance(request["body"], str):
                    # Convert hex string back to bytes
                    body = bytes.fromhex(request["body"])
                else:
                    body = request["body"]

        except Exception:
            # Fall back to simple path extraction for backward compatibility
            path = request_data.strip("/") or "index.html"
            method = "GET"
            query = ""
            headers = {}
            head_only = False
            body = None

        # Log the request
        print(f"[Server] {method} /{path}" + (f"?{query}" if query else ""))

        # Handle the request based on the method
        if method in ["GET", "HEAD"]:
            # Check if file exists
            file_path = os.path.join(WEB_ROOT, path)
            if not os.path.exists(file_path) or os.path.isdir(file_path):
                # Check for index.html in directory
                if os.path.isdir(file_path):
                    index_path = os.path.join(file_path, "index.html")
                    if os.path.exists(index_path):
                        file_path = index_path
                    else:
                        response = {
                            "status": 404,
                            "headers": {"Content-Type": "text/html"},
                            "content": "<html><body><h1>404 Not Found</h1><p>Directory index not available.</p></body></html>",
                        }
                        asyncio.create_task(
                            SERVER_API.app_call_reply(
                                call.call_id, str(response).encode()
                            )
                        )
                        return
                else:
                    response = {
                        "status": 404,
                        "headers": {"Content-Type": "text/html"},
                        "content": f"<html><body><h1>404 Not Found</h1><p>The requested file {path} was not found.</p></body></html>",
                    }
                    asyncio.create_task(
                        SERVER_API.app_call_reply(call.call_id, str(response).encode())
                    )
                    return

            # Get file content
            content_type = determine_content_type(file_path)

            if head_only:
                # For HEAD requests, don't include the body
                response = {
                    "status": 200,
                    "headers": {"Content-Type": content_type},
                    "content": "",
                }
            else:
                # For GET requests, include the file content
                with open(file_path, "rb") as f:
                    file_content = f.read()

                response = {
                    "status": 200,
                    "headers": {"Content-Type": content_type},
                    "content": "0x"
                    + file_content.hex(),  # Convert binary to hex string for transport
                }

        elif method == "POST":
            # Handle POST requests if needed
            response = {
                "status": 501,
                "headers": {"Content-Type": "text/html"},
                "content": "<html><body><h1>501 Not Implemented</h1><p>POST requests are not implemented yet.</p></body></html>",
            }
        else:
            # Unsupported method
            response = {
                "status": 405,
                "headers": {"Content-Type": "text/html"},
                "content": f"<html><body><h1>405 Method Not Allowed</h1><p>The method {method} is not supported.</p></body></html>",
            }

        # Send the response
        asyncio.create_task(
            SERVER_API.app_call_reply(call.call_id, str(response).encode())
        )
        print(f"[Server] Served {path} to {call.sender}")

    except Exception as e:
        print(f"[Server] Error handling request: {e}")
        error_response = {
            "status": 500,
            "headers": {"Content-Type": "text/html"},
            "content": f"<html><body><h1>500 Internal Server Error</h1><p>Error: {str(e)}</p></body></html>",
        }
        asyncio.create_task(
            SERVER_API.app_call_reply(call.call_id, str(response).encode())
        )


async def create_initial_route_and_dht():
    """Creates an initial route, publishes it to DHT, and stores the route ID."""
    global SERVER_API, CURRENT_ROUTE_ID, CURRENT_ROUTE_BLOB, CURRENT_RECORD_KEY
    async with await SERVER_API.new_routing_context() as rc:
        if not CURRENT_RECORD_KEY:
            record = await rc.create_dht_record(DHTSchema.dflt(1))
            CURRENT_RECORD_KEY = record.key

        existing_route_blob = await rc.get_dht_value(CURRENT_RECORD_KEY, ValueSubkey(0))

        if existing_route_blob:
            print("[Server] Existing route found in DHT, using it.")
            CURRENT_ROUTE_BLOB = existing_route_blob.data
            CURRENT_ROUTE_ID = await SERVER_API.import_remote_private_route(
                CURRENT_ROUTE_BLOB
            )
        else:
            print("[Server] No existing route found. Creating new route.")
            route_id, route_blob = await SERVER_API.new_private_route()
            CURRENT_ROUTE_ID = str(route_id)
            CURRENT_ROUTE_BLOB = route_blob

            await rc.set_dht_value(CURRENT_RECORD_KEY, ValueSubkey(0), route_blob)

            print("\n[Server] Created private route + DHT record.")
            print(f"         Route ID: {CURRENT_ROUTE_ID}")
            print(f"         DHT key:  {CURRENT_RECORD_KEY}\n")
            print("Clients can fetch subkey 0 of that DHT key to get the route blob.\n")


async def start_veilid_server():
    """Starts the Veilid web server and ensures DHT record is opened."""
    global SERVER_API, CURRENT_RECORD_KEY, WEB_ROOT

    # Initialize mime types
    mimetypes.init()

    # Ensure web root directory exists
    if not os.path.exists(WEB_ROOT):
        os.makedirs(WEB_ROOT)
        with open(os.path.join(WEB_ROOT, "index.html"), "w") as f:
            f.write(
                "<html><body><h1>Veilid Web Server</h1><p>Welcome to your Veilid web server!</p></body></html>"
            )

    # Connect to Veilid API
    SERVER_API = await json_api_connect_ipc(IPC_PATH, veilid_callback)

    # Set up DHT record and route
    if args.dht_key:
        CURRENT_RECORD_KEY = TypedKey(args.dht_key)
        print(f"[Server] Using provided DHT key: {CURRENT_RECORD_KEY}")

    await create_initial_route_and_dht()  # Ensures CURRENT_RECORD_KEY is set

    print(f"[Server] Serving files from: {os.path.abspath(WEB_ROOT)}")
    print("[Server] Running on Veilid...")

    # Keep the server running
    while True:
        await asyncio.sleep(10)


async def main():
    global WEB_ROOT

    # Set web root from command line argument
    if args.web_root:
        WEB_ROOT = args.web_root

    # Set up signal handlers
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        await start_veilid_server()
    except KeyboardInterrupt:
        handle_exit(None, None)
    except Exception as e:
        print(f"[Server] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

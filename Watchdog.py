import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from collections import defaultdict
import time
import logging
import ssl
import socket

# Setup the logging
logging.basicConfig(filename='firewall_activity.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Global settings for security checks
request_patterns = defaultdict(list)
blocklist = {'192.168.1.100', '10.0.0.2'}  # Example blocklisted IPs


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread to improve performance."""


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "ProxyHTTPRequestHandler/0.1"

    def rate_limit_check(self):
        """Checks if the number of requests from a single IP exceeds a set limit within a time window."""
        ip = self.client_address[0]
        current_time = time.time()
        window = 60  # time window in seconds
        max_requests = 10  # maximum allowed requests in the window
        access_times = request_patterns[ip]

        # Remove timestamps outside the current window
        request_patterns[ip] = [t for t in access_times if current_time - t < window]

        if len(request_patterns[ip]) >= max_requests:
            logging.warning(f"Rate limit exceeded for IP: {ip}")
            return False
        request_patterns[ip].append(current_time)
        return True

    def analyze_behavior(self):
        """Analyzes request intervals to detect potential flooding attacks."""
        ip = self.client_address[0]
        timestamps = request_patterns[ip]

        if len(timestamps) > 100:
            intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval < 0.1:  # interval in seconds
                logging.warning(f"Suspiciously high request frequency from IP: {ip}")
                return False
        return True

    def check_ip_blocklist(self):
        """Checks if the requesting IP is in the blocklist."""
        ip = self.client_address[0]
        if ip in blocklist:
            logging.warning(f"Blocked request from blacklisted IP: {ip}")
            return False
        return True

    def log_request(self, method):
        """Log and print all incoming requests for analysis."""
        ip = self.client_address[0]
        logging.info(f"Received {method} request from {ip} for {self.path}")
        print(f"Live log: {method} request from {ip} for {self.path}")

    def do_GET(self):
        """Handles GET requests by applying security checks and forwarding allowed requests."""
        self.log_request('GET')
        if not self.check_ip_blocklist() or not self.rate_limit_check() or not self.analyze_behavior():
            self.send_response(403)  # Forbidden
            self.end_headers()
            return
        self.proxy_request()

    def do_POST(self):
        """Handles POST requests with security validations before forwarding them."""
        self.log_request('POST')
        if self.path == 'white list implations': # add webhook / or other ip's
            # Bypass security checks for requests to /nataly-whatsapp
            self.proxy_request(post=True)
        else:
            # Apply security checks for other requests
            if not self.check_ip_blocklist() or not self.rate_limit_check() or not self.analyze_behavior():
                self.send_response(403)  # Forbidden
                self.end_headers()
                return
            self.proxy_request(post=True)

    def proxy_request(self, post=False):
        """Proxy the request to the internal Flask server, preserving the method (GET or POST)."""
        if not self.check_ip_blocklist() or not self.rate_limit_check() or not self.analyze_behavior():
            self.send_response(403)  # Forbidden
            self.end_headers()
            return

        try:
            # Create a socket connection to the Flask server
            server_address = ('127.0.0.1', 5001)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(server_address)

            # Send the original request data as-is to the Flask server
            request_data = f"{self.command} {self.path} {self.request_version}\r\n"
            for header, value in self.headers.items():
                request_data += f"{header}: {value}\r\n"
            request_data += "\r\n"
            if post:
                content_length = int(self.headers.get('Content-Length', 0))
                request_data += self.rfile.read(content_length)

            sock.sendall(request_data.encode())

            # Receive the response from the Flask server
            response_data = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response_data += data

            # Send the response back to the client
            self.wfile.write(response_data)
            self.wfile.flush()

            sock.close()
        except Exception as e:
            logging.error(f"Error proxying request to Flask server: {e}")
            self.send_error(502)


if __name__ == '__main__':
    server_address = ('192.168.1.1', 443)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(httpd.socket,
                                   certfile=r'path/to.pem',
                                   keyfile=r'path/to/private.key', server_side=True)
    logging.info("Proxy server is running")
    httpd.serve_forever()

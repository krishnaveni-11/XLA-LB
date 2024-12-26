from http.server import SimpleHTTPRequestHandler, HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import logging
import threading
import time

# Global variables
ewa_latency = None
ewa_request_count = None
alpha = 0.5

latency_lock = threading.Lock()  # Lock for thread safety
request_count_lock = threading.Lock()  # Lock for thread safety
connection_count = 0
request_count = 0
lock = threading.Lock()
# Set up two loggers: one for general logging, one for latency logging to a file
logging.basicConfig(level=logging.INFO)  # General logger (console)

# Create a separate logger for latency logging: for analysis purpose
latency_logger = logging.getLogger('latency_logger')
latency_logger.setLevel(logging.INFO)

# Set up file handler for latency logging
latency_log_file_handler = logging.FileHandler('latency_log.txt', mode='a')
latency_log_file_handler.setLevel(logging.INFO)

# Define the format for latency logging
formatter = logging.Formatter('%(asctime)s - %(message)s')
latency_log_file_handler.setFormatter(formatter)

# Add the handler to the latency logger
latency_logger.addHandler(latency_log_file_handler)

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class CustomHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        global ewa_latency, ewa_request_count, request_count
        global connection_count
        with lock:
            connection_count += 1  # Increment connection count
       
        # Log the number of active threads at the start of request handling
        active_threads = threading.active_count()

        # Update request count
        with request_count_lock:
            request_count += 1
            if ewa_request_count is None:
                ewa_request_count = request_count
            else:
                ewa_request_count = alpha * request_count + (1 - alpha) * ewa_request_count
       
        logging.info("Starting request handling. Active threads: {}, Requests handling: {}, EWA Request Count: {:.2f}".format(
            active_threads, request_count, ewa_request_count))

        # Serve the file and measure latency
        file_path = './index.html'
        start_time = time.time()
        try:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open(file_path, 'rb') as file:
                self.wfile.write(file.read())

            # Measure and log latency
            latency = (time.time() - start_time) * 1000  # Convert to milliseconds
            latency_logger.info("GET /index.html latency: {:.2f}ms".format(latency))  # Log to file

            with latency_lock:  # Ensure safe access to ewa_latency
                if ewa_latency is None:
                    ewa_latency = latency
                else:
                    ewa_latency = alpha * latency + (1 - alpha) * ewa_latency

            logging.info("Updated EWA Latency: {:.2f}ms".format(ewa_latency))
        except Exception as e:
            logging.error("Error handling request: {}".format(e))
            self.send_error(500, "Server error: {}".format(e))
            return

        # Update request count after handling
        with request_count_lock:
            request_count -= 1
            if ewa_request_count is None:
                ewa_request_count = request_count
            else:
                ewa_request_count = alpha * request_count + (1 - alpha) * ewa_request_count
       
        logging.info("Request count after handling request: {}, EWA Request Count: {:.2f}".format(
            request_count, ewa_request_count))

class LatencyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global ewa_latency, ewa_request_count, request_count

        if self.path == '/latency':
            try:
                with latency_lock:  # Ensure safe access to ewa_latency
                    latency_value = ewa_latency if ewa_latency is not None else 0
                with request_count_lock:  # Ensure safe access to ewa_request_count
                    ewa_request_count_value = ewa_request_count if ewa_request_count is not None else 0
                    request_count_value = request_count

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(bytes('{{"ewa_latency": "{:.2f}", "ewa_request_count": "{:.2f}"}}'.format(
                    latency_value, ewa_request_count_value), 'utf-8'))
                logging.info("Returned EWA Latency: {:.2f}ms, EWA Request Count: {:.2f}, and Request Count: {}".format(
                    latency_value, ewa_request_count_value, request_count_value))
            except Exception as e:
                logging.error("Error in LatencyHandler: {}".format(e))
                self.send_response(500)
                self.end_headers()
                self.wfile.write(bytes('Error: {}'.format(e), 'utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run_main_server():
    server_address = ('', 80)
    httpd = ThreadingHTTPServer(server_address, CustomHandler)
    logging.info('Starting main server on port 80...')
    httpd.serve_forever()

def run_latency_server():
    server_address = ('', 8081)
    httpd = HTTPServer(server_address, LatencyHandler)
    logging.info('Starting latency server on port 8081...')
    httpd.serve_forever()

def print_connections_per_second():
    global connection_count
    while True:
        time.sleep(1)
        with lock:
            log_message = "Connections per second: {}\n".format(connection_count)
            with open("connections.log", "a") as log_file:
                log_file.write(log_message)
            #print(log_message)  # Optionally print to console
            connection_count = 0  # Reset counter

if __name__ == "__main__":
    threading.Thread(target=run_main_server).start()
    threading.Thread(target=run_latency_server).start()
    threading.Thread(target=print_connections_per_second, daemon=True).start()

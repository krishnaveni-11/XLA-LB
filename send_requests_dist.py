import concurrent.futures
import requests
import time
import threading
import random  # Import the random module

# URLs to randomly choose from
urls = [
    'http://172.17.0.5:80',
     'http://172.17.0.7:80',
     'http://172.17.0.4:80',
     
    
       
]

initial_requests = 10
increment_step = 3
max_requests = 30 # Maximum number of requests at any point
content_filename = 'web_content.txt'
batch_times = []  # List to store response times for each batch
log_filename = 'log.txt'  # Name of the file where logs will be written
file_lock = threading.Lock()
time_lock = threading.Lock()
log_lock = threading.Lock()

latency_urls = [
    'http://172.17.0.10:8081/latency',
    'http://172.17.0.11:8081/latency',
    'http://172.17.0.12:8081/latency',
    'http://172.17.0.13:8081/latency',
    'http://172.17.0.14:8081/latency',
    'http://172.17.0.15:8081/latency',
    'http://172.17.0.16:8081/latency',
    'http://172.17.0.17:8081/latency'
]

def log_message(message):
    try:
        with log_lock:
            with open(log_filename, 'a') as log_file:
                log_file.write(message + "\n")
    except IOError as e:
        print(f"Error writing to log file: {e}")

def send_request(file_obj):
    # Randomly select a URL from the list
    url = random.choice(urls)
    try:
        thread_name = threading.current_thread().name
        print(f"[Thread-{thread_name}] Sending request to {url}")
        response = requests.get(url, timeout=120)  # Set a timeout of 120 seconds
        if response.status_code == 200:
            print("Content obtained")
            # Uncomment the next lines if you want to save the content to a file
            # with file_lock:  # Lock the file before writing
            #     file_obj.write(response.text.strip() + "\n")
        else:
            print(f"Request failed with status code: {response.status_code}")
    except requests.Timeout:
        print(f"[Thread-{thread_name}] Request timed out.")
    except requests.RequestException as e:
        print(f"[Thread-{thread_name}] Request failed: {e}")

def send_requests_concurrently(num_requests, file_obj, batch_number):
    start_time = time.time()  # Start time of the batch
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
        futures = []
        for _ in range(num_requests):
            future = executor.submit(send_request, file_obj)  # No URL passed here, it will be selected inside send_request
            futures.append(future)

    def record_time_when_done(futures, batch_number):
        concurrent.futures.wait(futures)  # Wait for all requests to complete for this batch
        end_time = time.time()
        batch_time_ms = (end_time - start_time) * 1000  # Convert to milliseconds
        with time_lock:
            batch_times.append((batch_number, batch_time_ms))
        print(f"Batch {batch_number} of {num_requests} requests took {batch_time_ms:.2f} ms")
        message = f"Batch {batch_number} of {num_requests} requests took {batch_time_ms:.2f} ms"
        log_message(message)

    # Start background thread to monitor and record the batch completion time
    #threading.Thread(target=record_time_when_done, args=(futures, batch_number)).start()

def trigger_batch(num_requests, batch_number):
    print(f"Triggering {num_requests} requests for batch {batch_number}.")
    message = f"Triggering {num_requests} requests for batch {batch_number}."
    log_message(message)
    send_requests_concurrently(num_requests, None, batch_number)

def send_latency_request(url):
    """Send a request to check latency and print the response."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            latency = response.text.strip()
            print(f"Latency response from {url}: {latency}")
        else:
            print(f"Failed to get latency from {url}, status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error while getting latency from {url}: {e}")

def check_latencies():
    """Send latency requests to all predefined URLs."""
    for latency_url in latency_urls:
        send_latency_request(latency_url)

def main(): 
    num_requests = initial_requests  # Starting query rate
    batch_number = 1  # Track batch numbers
    
    #while batch_number <= 7:  # Uncomment me for constant query rate
    while num_requests<= max_requests:
        # Step 1: Check latencies before starting the batch
        # print(f"Checking latencies before firing batch {batch_number}...")
        # check_latencies()

        # Step 2: Start a new thread to trigger each batch without waiting for previous ones
        batch_thread = threading.Thread(target=trigger_batch, args=(num_requests, batch_number))
        batch_thread.start()

        # Increment the number of requests for the next batch and batch counter
        num_requests += increment_step  # Uncomment me for query rate
        batch_number += 1

        # Sleep for 1 second before launching the next batch
        time.sleep(1)
        
    # print(f"Checking latencies after firing batch {batch_number}...")
    # check_latencies()

if __name__ == "__main__":
    main()

import requests
import time
import statistics

def measure_latency(domains, num_requests=3):
    """
    Measures the latency to a list of domains and returns a dictionary of results.
    
    Args:
        domains (list): A list of domain names to test.
        num_requests (int): The number of times to test each domain for a more stable average.
        
    Returns:
        dict: A dictionary with domains as keys and their average latency in milliseconds as values.
              Returns an empty dictionary if an error occurs.
    """
    latencies = {}
    print("--- Starting Latency Test ---")

    for domain in domains:
        url = f"https://{domain}"
        domain_latencies = []
        try:
            for i in range(num_requests):
                # Start timer
                start_time = time.perf_counter()
                
                # Send HTTP GET request
                # timeout=5 sets a 5-second timeout for the request.
                # verify=True ensures SSL certificates are verified, which is important when an SWG is doing SSL inspection.
                response = requests.get(url, timeout=5, verify="dope.security.root.crt")
                
                # Stop timer
                end_time = time.perf_counter()
                
                # Calculate the elapsed time in milliseconds
                elapsed_time_ms = (end_time - start_time) * 1000
                domain_latencies.append(elapsed_time_ms)
                
                print(f"  {i+1}/{num_requests} -> {url}: {elapsed_time_ms:.2f} ms (Status: {response.status_code})")
                
                # A small delay between requests to the same domain
                time.sleep(0.5)

            # Calculate the average latency for the current domain
            avg_latency = statistics.mean(domain_latencies)
            latencies[domain] = avg_latency
            print(f"-> Average for {url}: {avg_latency:.2f} ms\n")

        except requests.exceptions.RequestException as e:
            print(f"Could not connect to {url}. Error: {e}\n")
            latencies[domain] = None # Indicate failure for this domain

    return latencies

if __name__ == "__main__":
    # List of 20 popular domains to test
    popular_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com",
        "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
        "microsoft.com", "apple.com", "netflix.com", "reddit.com",
        "office.com", "yahoo.com", "bing.com", "salesforce.com",
        "ebay.com", "cnn.com", "nytimes.com", "github.com"
    ]
    
    # Run the latency measurement
    results = measure_latency(popular_domains, num_requests=5)
    
    # --- Analysis of Results ---
    successful_results = [lat for lat in results.values() if lat is not None]
    
    if successful_results:
        overall_average = statistics.mean(successful_results)
        min_latency = min(successful_results)
        max_latency = max(successful_results)
        std_dev = statistics.stdev(successful_results) if len(successful_results) > 1 else 0

        print("\n--- Overall Latency Statistics ---")
        print(f"Total domains tested: {len(popular_domains)}")
        print(f"Successfully connected: {len(successful_results)}")
        print(f"Overall Average Latency: {overall_average:.2f} ms")
        print(f"Minimum Latency: {min_latency:.2f} ms")
        print(f"Maximum Latency: {max_latency:.2f} ms")
        print(f"Standard Deviation (σ): {std_dev:.2f} ms")
    else:
        print("\nNo successful connections were made.")

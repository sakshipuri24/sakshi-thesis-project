import requests
import time
import statistics
import argparse
import os

import warnings
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
warnings.simplefilter("ignore", InsecureRequestWarning)


def measure_latency(domains, num_requests=3, verify_cert=True):
    """
    Measures the latency to a list of domains and returns a dictionary of results.

    Args:
        domains (list): A list of domain names to test.
        num_requests (int): The number of times to test each domain.
        verify_cert (str|bool): Path to CA cert bundle or True/False.

    Returns:
        dict: Domain -> average latency in ms (or None on failure)
    """
    latencies = {}
    print("--- Starting Latency Test ---")

    for domain in domains:
        url = f"https://{domain}"
        domain_latencies = []
        try:
            for i in range(num_requests):
                start_time = time.perf_counter()

                response = requests.get(url, timeout=5, verify=verify_cert)

                end_time = time.perf_counter()
                elapsed_time_ms = (end_time - start_time) * 1000
                domain_latencies.append(elapsed_time_ms)

                print(f"  {i+1}/{num_requests} -> {url}: {elapsed_time_ms:.2f} ms (Status: {response.status_code})")
                time.sleep(0.5)

            avg_latency = statistics.mean(domain_latencies)
            latencies[domain] = avg_latency
            print(f"-> Average for {url}: {avg_latency:.2f} ms\n")

        except requests.exceptions.RequestException as e:
            print(f"Could not connect to {url}. Error: {e}\n")
            latencies[domain] = None

    return latencies


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Latency tester with optional CA certificate support.")
    parser.add_argument("--ca-cert", help="Path to custom CA certificate bundle (PEM format)")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification (NOT recommended)")
    args = parser.parse_args()

    # Determine SSL verification mode
    if args.insecure:
        verify_cert = False
    elif args.ca_cert:
        verify_cert = args.ca_cert
    elif os.getenv("REQUESTS_CA_BUNDLE"):
        verify_cert = os.getenv("REQUESTS_CA_BUNDLE")
    else:
        verify_cert = True

    popular_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com",
        "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
        "microsoft.com", "apple.com", "netflix.com", "reddit.com",
        "office.com", "yahoo.com", "bing.com", "salesforce.com",
        "ebay.com", "cnn.com", "nytimes.com", "github.com"
    ]

    results = measure_latency(popular_domains, num_requests=5, verify_cert=verify_cert)

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

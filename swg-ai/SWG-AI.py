"""
Program: SWG AI tool 
Version: 1.0
Author: Sakshi Puri
Email: sakshi.puri@mtu.ie
Roll Number: R00257762
Course: MSc in CyberSecurity at MTU, Cork
Thesis: Evaluating and Investigating the Evolution of Secure Web Gateway (SWG) as part of the Secure Access Service Edge (SASE)
Date: July 2025

Description:
    This mitmproxy addon acts as a Secure Web Gateway (SWG) by intercepting HTTP/HTTPS traffic,
    categorizing URLs using the Google Gemini AI model, and enforcing access policies.
    It maintains a cache of previously categorized domains to reduce AI API calls and improve performance.
    New categories identified by the AI are automatically added to a policy file (`categories.json`)
    with an "allowed" status by default, enabling dynamic policy updates.
    Domains falling under "blocked" categories (as defined in `categories.json`) are prevented from loading,
    and a custom block page is served to the user.
    The addon also logs all activities, including AI categorization latency and total processing time for requests.

Features:
    - **URL Categorization**: Uses Google Gemini AI to categorize website domains.
    - **Caching**: Stores domain categories in `domain_cache.json` to minimize repeated AI calls.
    - **Dynamic Policy Update**: Automatically adds newly encountered categories to `categories.json` as "allowed".
    - **Policy Enforcement**: Blocks access to domains belonging to categories marked as "blocked" in `categories.json`.
    - **Custom Block Page**: Serves a user-friendly HTML block page for forbidden access.
    - **Logging**: Detailed logging of intercepted domains, categorization results, AI latency, and blocking actions.
    - **Latency Measurement**: Measures and logs the time taken for AI categorization and total request processing.

Files:
    - `SWG-AI.py`: The main mitmproxy addon script.
    - `categories.json`: Defines URL categories and their policy (allowed/blocked).
      Example: `{"Social Media": "blocked", "News": "allowed"}`
    - `domain_cache.json`: Cache file for storing previously categorized domains.
    - `block_page.html`: Custom HTML page displayed when a domain is blocked.
    - `logs.txt`: Log file for all addon activities.

Usage:
    1. Install mitmproxy: `pip install mitmproxy`
    2. Install tldextract: `pip install tldextract`
    3. Set your Google Gemini API key in as an environment variable `GOOGLE_API_KEY`.
    4. Run mitmproxy with this script: `mitmproxy -s SWG-AI.py`

"""
import time
import logging
from mitmproxy import http
import tldextract
import google.generativeai as genai
import os
import json

# --- Configure Logging ---
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

file_handler = logging.FileHandler('logs.txt')
file_handler.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

# --- Gemini API Configuration ---
api_key = os.environ.get("GOOGLE_API_KEY", "")
genai.configure(api_key=api_key)

#  Initialize the Gemini model  
model = genai.GenerativeModel('gemini-2.5-flash') 
#model = genai.GenerativeModel('gemini-1.5-flash-latest') 


class URLCategorizer:
    def __init__(self):
        logger.debug("URLCategorizer addon initialized.")
        self.category_cache = {}
        self.load_cache_from_file('domain_cache.json')
        
        # --- Load Blocked Categories from Categories File ---
        self.blocked_categories = self._load_blocked_categories('categories.json')
        logger.info(f"Loaded Blocked Categories: {self.blocked_categories}")

        # --- Load Block Page HTML from File ---
        self.block_page_html = self._load_block_page_html('block_page.html')
        if not self.block_page_html:
            logger.warning("Block page HTML could not be loaded. Default block page will be used.")
            # Provide a fallback generic block page or exit
            self.block_page_html = "<h1>Access Denied!</h1><p>Blocked by filter.</p>"

    def _load_blocked_categories(self, filename):
        """Loads blocked categories from a categories json file."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                category_policies = json.load(f)

            # Get only the categories that are blocked
            blocked_categories = {cat for cat, status in category_policies.items() if status.lower() == "blocked"}    
            return set(blocked_categories) # Use a set for faster lookup
        except FileNotFoundError:
            # If the categories file does not exist, create it with an empty dict
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump({}, f)
            logger.warning(f"Blocked categories file '{filename}' not found. Created new empty file.")
            return set()
        except Exception as e:
            logger.error(f"Error loading blocked categories from '{filename}': {e}")
            return set()

    def _load_block_page_html(self, filename):
        """Loads block page HTML from a file."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"Block page HTML file '{filename}' not found.")
            return None
        except Exception as e:
            logger.error(f"Error loading block page HTML from '{filename}': {e}")
            return None


    def load_cache_from_file(self, filename):
        try:
            with open(filename, 'r') as f:
                self.category_cache = json.load(f)
            logger.debug(f"Loaded {len(self.category_cache)} items from cache file '{filename}'.")
        except FileNotFoundError:
            # Create an empty cache file if not found
            with open(filename, 'w') as f:
                json.dump({}, f)
            self.category_cache = {}
            logger.info(f"Cache file '{filename}' not found. Created new empty cache file.")
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from cache file '{filename}'. Starting with empty cache.")
            self.category_cache = {}

    def save_cache_to_file(self, filename):
        try:
            with open(filename, 'w') as f:
                json.dump(self.category_cache, f, indent=4)
            logger.debug(f"Saved {len(self.category_cache)} items to cache file '{filename}'.")
        except Exception as e:
            logger.error(f"Error saving cache to file '{filename}': {e}")


    def request(self, flow: http.HTTPFlow):
        total_start = time.time()
        if flow.request.pretty_host:
            extracted = tldextract.extract(flow.request.pretty_host)
            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

            if not domain:
                logger.warning(f"Could not extract a valid domain from {flow.request.pretty_host}")
                return

            logger.debug(f"Intercepted Domain: {domain}")

            # --- Caching Check ---
            category = self.category_cache.get(domain)
            if category:
                logger.debug(f"Domain: {domain}, Category: {category} (Cached)")
            else:
                # Get category using Gemini
                start_time = time.time()
                category = self.get_domain_category(domain)
                if not category:
                    logger.error(f"Failed to categorize domain {domain}. No category returned.")
                    return
                ai_latency = time.time() - start_time
                logger.info(f"AI latency for domain {domain}: {ai_latency * 1000:.2f} ms")

                # --- Update categories.json if category is new ---
                try:
                    with open("categories.json", "r") as f:
                        category_policies = json.load(f)
                except FileNotFoundError:
                    category_policies = {}

                if category not in category_policies:
                    category_policies[category] = "allowed"
                    if category != "Error (Gemini API)":
                        with open("categories.json", "w") as f:
                            json.dump(category_policies, f, indent=4)
                            logger.debug(f"Added new category to policy: {category} = allowed")

                self.category_cache[domain] = category # Cache the new category
                self.save_cache_to_file('domain_cache.json') # Save cache after each new entry (or periodically)
                logger.debug(f"Domain: {domain}, Category: {category} (Gemini)")
            logger.debug(f"Total processing time for allowed domain {domain}: {time.time() - total_start:.4f} seconds")
            
            # --- Blocking Logic ---
            # Check if the categorized domain is in the loaded blocked categories
            
            if category in self.blocked_categories:
                logger.warning(f"Blocking {domain} - Category: {category}")
                print("DEBUG: Block page should be served now!")  # Add this line for debugging
                #flow.kill()
                flow.response = http.Response.make(
                    403,
                    self.block_page_html,
                    {"Content-Type": "text/html"}
                )
                # flow.response = http.Response.make(
                #                         403,  # status code
                #                         f"<html><body><h1>Access Blocked</h1><p>is categorized as and has been blocked.</p></body></html>",
                #                         {"Content-Type": "text/html"}
                #                 )
                logger.debug(f"Total processing time for domain {domain}: {time.time() - total_start:.4f} seconds")
                return  # Stop further processing

    def get_domain_category(self, domain: str) -> str:
        prompt = f"""
        You are a cybersecurity expert helping categorize website domains based on their most likely purpose or threat level.

        Use only one of the following category labels:
        - Social Media
        - News
        - Video Streaming
        - E-commerce
        - Software Development
        - Cloud Storage
        - Communication
        - Search Engine
        - Phishing
        - Malware
        - Suspicious
        - Encyclopedia
        - Business
        - Content Delivery Network
        - Adult Content
        - Pornography
        - Healthcare
        - Information Technology
        - Travel
        - Education
        - Entertainment
        - Shopping
        - Vehicles
        - Games
        - Drugs
        - AI/ML

    

        Guidelines:
        - If the domain appears dangerous, contains misspellings, obscure TLDs, or is linked to harmful behavior, choose 'Malware' or 'Phishing'.
        - Use 'Malware' for domains that are likely hosting malicious software or malware distribution.
        - Use 'Phishing' for domains pretending to be legitimate to steal information.
        - Use 'Suspicious' for odd or generic domains that might be harmful but aren't clearly phishing or malware.
        - Even if the domain is unfamiliar, use your judgment based on common threat indicators or name patterns.
        - If still unsure, return 'Unknown'.

        Examples:
        - google.com → Search Engine  
        - instagram.com → Social Media  
        - nytimes.com → News  
        - github.com → Software Development  
        - dropbox.com → Cloud Storage  
        - bankofamerica-login.com → Phishing  
        - update-your-browser-info.ru → Malware  
        - suspicious-checker.xyz → Suspicious  
        - xakjduqw.net → Suspicious  
        - malicious-update-download.com → Malware  

        Domain: {domain}
        Category:
        """


        # prompt = f"""
        # Categorize the following website domain. Provide only the primary category name.
        # If you are unsure, categorize it as 'Unknown'.

        # Examples:
        # google.com: Search Engine
        # drive.google.com: Cloud Storage
        # instagram.com: Social Media
        # youtube.com: Video Streaming
        # amazon.com: E-commerce
        # github.com: Software Development
        # nytimes.com: News
        # wikipedia.org: Encyclopedia
        # slack.com: Communication
        # example.net: Unknown
        
        # Domain to categorize: {domain}
        # Category:
        # """
        try:
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(temperature=0.0)
            )
            category = response.text.strip()
            logger.info(f"Gemini API returned category '{category}' for domain '{domain}'")
            if ":" in category:
                category = category.split(":")[-1].strip()
            
            if len(category) > 50:
                 logger.warning(f"Gemini returned an unusual category for {domain}: '{category}'. Defaulting to Unknown.")
                 return "Unknown"

            return category

        except Exception as e:
            logger.error(f"Error categorizing domain '{domain}' with Gemini API: {e}")
            return ""

addons = [URLCategorizer()]
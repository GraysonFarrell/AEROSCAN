import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import urllib.parse
from bs4 import BeautifulSoup
import time
import logging
from collections import deque

# Suppress only the single InsecureRequestWarning from urllib3 if user opts out
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Setting up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Banner (Updated to fix invalid escape sequences)
banner = r"""
 .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .----------------.  .-----------------.
| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |
| |      __      | || |  _________   | || |  _______     | || |     ____     | || |    _______   | || |     ______   | || |      __      | || | ____  _____  | |
| |     /  \     | || | |_   ___  |  | || | |_   __ \    | || |   .'    `.   | || |  |  (__ \_|  | || |  / .'   \_|  | || |     /  \     | || ||_   \|_   _| | |
| |    / /\ \    | || |   | |_  \_|  | || |   | |__) |   | || |  /  .--.  \  | || |  |  (__ \_|  | || |  / .'   \_|  | || |    / /\ \    | || |  |   \ | |   | |
| |   / ____ \   | || |   |  _|  _   | || |   |  __ /    | || |  | |    | |  | || |   '.___`-.   | || |  | |         | || |   / ____ \   | || |  | |\ \| |   | |
| | _/ /    \ \_ | || |  _| |___/ |  | || |  _| |  \ \_  | || |  \  `--'  /  | || |  |`\____) |  | || |  \ `.___.'\  | || | _/ /    \ \_ | || | _| |_\   |_  | |
| ||____|  |____|| || | |_________|  | || | |____| |___| | || |   `.____.'   | || |  |_______.'  | || |   `._____.'  | || ||____|  |____|| || ||_____|\____| | |
| |              | || |              | || |              | || |              | || |              | || |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'  '----------------'   """

def xss_scan(url, rate_limit_enabled=False, delay=1):
    try:
        with open('xss_payloads.txt', 'r') as file:
            payloads = file.readlines()

        # Send a GET request to fetch the page content
        response = requests.get(url, verify=False)
        if response.status_code != 200:
            logger.error(f"Failed to retrieve the page. Status code: {response.status_code}")
            return

        # Parse the page content using BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')  # Find all forms on the page

        if not forms:
            logger.info("No forms found on the page.")
            return

        logger.info(f"Found {len(forms)} form(s) on the page.")

        for form in forms:
            inputs = form.find_all('input')
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')

                # Only proceed with text-based inputs
                if input_type in ['text', 'search', 'email', 'url', 'password', 'textarea']:
                    logger.info(f"Injecting payloads into input: {input_name or 'Unnamed'}")

                    for payload in payloads:
                        payload = payload.strip()
                        data = {input_name: payload}

                        # Handle relative URLs
                        action = form.get('action', url)
                        action_url = urllib.parse.urljoin(url, action)
                        method = form.get('method', 'get').lower()

                        # Send form data based on method
                        try:
                            if method == 'post':
                                form_response = requests.post(action_url, data=data, verify=False)
                            else:
                                form_response = requests.get(action_url, params=data, verify=False)

                            # Check if payload is reflected in the response
                            encoded_payload = urllib.parse.quote(payload)
                            if payload in form_response.text or encoded_payload in form_response.text:
                                logger.warning(f"XSS vulnerability found with payload: {payload}")
                            else:
                                logger.info(f"No XSS vulnerability found with payload: {payload}")

                        except requests.RequestException as e:
                            logger.error(f"Error submitting form: {e}")

                        if rate_limit_enabled:
                            time.sleep(delay)

    except FileNotFoundError:
        logger.error("XSS payload file not found. Please ensure 'xss_payloads.txt' is in the same directory as the script.")

def crawl_and_scan(start_url, rate_limit_enabled=False, delay=1):
    visited_urls = set()
    urls_to_visit = deque([start_url])

    while urls_to_visit:
        current_url = urls_to_visit.popleft()
        if current_url in visited_urls:
            continue

        visited_urls.add(current_url)
        logger.info(f"Crawling: {current_url}")

        try:
            response = requests.get(current_url, verify=False)
            if response.status_code != 200:
                logger.warning(f"Failed to retrieve the page. Status code: {response.status_code}")
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                full_url = urllib.parse.urljoin(current_url, href)
                if full_url.startswith(start_url) and full_url not in visited_urls:
                    # Scan the found URL for XSS before continuing with the next link
                    xss_scan(full_url, rate_limit_enabled, delay)
                    urls_to_visit.append(full_url)

            if rate_limit_enabled:
                time.sleep(delay)

        except requests.RequestException as e:
            logger.error(f"Error crawling {current_url}: {e}")

    return visited_urls

def main():
    print(banner)
    start_url = input("Enter the URL to scan for XSS: ")

    # Ask the user if they want to enable rate limiting
    rate_limit_enabled = input("Do you want to enable rate limiting? (yes/no): ").strip().lower() == 'yes'

    # Initialize delay with a default value
    delay = 1

    if rate_limit_enabled:
        delay = float(input("Enter the delay duration in seconds: ").strip())

    # Ask if crawling is enabled
    crawl_enabled = input("Do you want to enable web crawling? (yes/no): ").strip().lower() == 'yes'

    # Now crawl the website first if enabled
    if crawl_enabled:
        logger.info("Starting web crawl...")
        crawl_and_scan(start_url, rate_limit_enabled, delay)
    else:
        # Only scan the start URL directly without crawling
        xss_scan(start_url, rate_limit_enabled, delay)

if __name__ == "__main__":
    main()

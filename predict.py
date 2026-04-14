import re
from urllib.parse import urlparse
import requests
import whois
from datetime import datetime
from bs4 import BeautifulSoup
import socket


import pandas as pd
import joblib
# Load trained model
import pickle
model = joblib.load("phishing_model.pkl")
# Load column names
with open("columns.pkl", "rb") as f:
    columns = pickle.load(f)


def having_ip_address(url='https://www.brightika.com'):
    # Check for IPv4 address
    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        return -1

    # Check for hexadecimal IP (like 0x58.0xCC...)
    if re.search(r'0x[0-9a-fA-F]+', url):
        return -1

    return 1

def url_length_feature(url):
    length = len(url)

    if length < 54:
        return 1
    elif 54 <= length <= 75:
        return 0
    else:
        return -1

def shortening_service_feature(url):
    shortening_services = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "bit.do", "cutt.ly",
    "shorturl.at", "rb.gy", "rebrand.ly"
]

    if any(service in url for service in shortening_services):
        return -1
    else:
        return 1

def having_at_symbol_feature(url):
    if "@" in url:
        return -1
    else:
        return 1

def double_slash_redirecting_feature(url):
    # Find last occurrence of '//'
    last_double_slash = url.rfind('//')

    # Check expected position
    if url.startswith("https"):
        if last_double_slash > 7:
            return -1
    else:
        if last_double_slash > 6:
            return -1

    return 1

def prefix_suffix_feature(url):
    domain = urlparse(url).netloc

    if '-' in domain:
        return -1
    else:
        return 1

def having_sub_domain_feature(url):
    domain = urlparse(url).netloc

    # Remove 'www.'
    if domain.startswith("www."):
        domain = domain[4:]

    # Count dots
    dot_count = domain.count('.')

    if dot_count == 1:
        return 1      # no subdomain
    elif dot_count == 2:
        return 0      # one subdomain
    else:
        return -1     # multiple subdomains

def sslfinal_state_feature(url):
    try:
        if not url.startswith("http"):
            url = "http://" + url

        response = requests.get(url, timeout=5)

        if response.url.startswith("https"):
            return 1
        else:
            return -1
    except:
        return -1

def domain_registration_length_feature(url):
    try:
        domain = urlparse(url).netloc

        # Remove 'www.'
        if domain.startswith("www."):
            domain = domain[4:]

        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date
        expiration_date = domain_info.expiration_date

        # Handle list format (sometimes WHOIS returns list)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        # If any value is missing
        if creation_date is None or expiration_date is None:
            return -1

        # Calculate registration length
        duration = (expiration_date - creation_date).days

        if duration >= 365:
            return 1
        else:
            return -1

    except:
        return -1  # If WHOIS fails

def favicon_feature(url):
    try:
        # Normalize URL
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        domain = urlparse(url).netloc

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # Find favicon link
        icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())

        if icon_link and icon_link.get("href"):
            favicon_url = icon_link.get("href")

            # Check if favicon URL belongs to same domain
            if domain in favicon_url or favicon_url.startswith("/"):
                return 1
            else:
                return -1

        return 1  # No favicon found → assume safe

    except:
        return -1

def port_feature(url):
    try:
        parsed = urlparse(url)

        # If no port is specified → default → safe
        if parsed.port is None:
            return 1

        # Check standard ports
        if parsed.port in [80, 443]:
            return 1
        else:
            return -1

    except:
        return -1

def https_token_feature(url):
    domain = urlparse(url).netloc.lower()

    if "https" in domain:
        return -1
    else:
        return 1

def request_url_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        domain = urlparse(url).netloc

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        tags = soup.find_all(['img', 'audio', 'embed', 'iframe'])

        total = len(tags)
        external = 0

        for tag in tags:
            src = tag.get('src')
            if src:
                if domain not in src and not src.startswith('/'):
                    external += 1

        if total == 0:
            return 1  # no resources → assume safe

        percentage = external / total

        if percentage < 0.22:
            return 1
        else:
            return -1

    except:
        return -1

def url_of_anchor_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        domain = urlparse(url).netloc

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        anchors = soup.find_all('a')

        total = len(anchors)
        unsafe = 0

        for tag in anchors:
            href = tag.get('href')

            if href:
                # Empty or unsafe links
                if href.startswith("#") or \
                   href.lower().startswith("javascript") or \
                   href.lower().startswith("mailto"):
                    unsafe += 1

                # External domain
                elif domain not in href and not href.startswith('/'):
                    unsafe += 1

        if total == 0:
            return 1

        percentage = unsafe / total

        if percentage < 0.31:
            return 1
        elif percentage <= 0.67:
            return 0
        else:
            return -1

    except:
        return -1

def links_in_tags_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        domain = urlparse(url).netloc

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        tags = (
            soup.find_all('meta') +
            soup.find_all('script') +
            soup.find_all('link')
        )

        total = len(tags)
        external = 0

        for tag in tags:
            src = tag.get('src') or tag.get('href')

            if src:
                if domain not in src and not src.startswith('/'):
                    external += 1

        if total == 0:
            return 1

        percentage = external / total

        if percentage < 0.17:
            return 1
        elif percentage <= 0.81:
            return 0
        else:
            return -1

    except:
        return -1

def sfh_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        domain = urlparse(url).netloc

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all('form')

        if len(forms) == 0:
            return 1  # no forms → assume safe

        for form in forms:
            action = form.get('action')

            if action is None or action == "" or action.lower() == "about:blank":
                return -1  # phishing

            # Check external domain
            elif domain not in action and not action.startswith('/'):
                return 0  # suspicious

        return 1  # safe

    except:
        return -1

def submitting_to_email_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # Check forms
        forms = soup.find_all('form')

        for form in forms:
            action = form.get('action')
            if action and "mailto:" in action.lower():
                return -1

        # Check page content (extra safety)
        if "mailto:" in response.text.lower():
            return -1

        return 1

    except:
        return -1

def abnormal_url_feature(url):
    try:
        domain = urlparse(url).netloc

        if domain.startswith("www."):
            domain = domain[4:]

        domain_info = whois.whois(domain)

        # If no WHOIS info → phishing
        if domain_info.domain_name is None:
            return -1

        return 1

    except:
        return -1

def redirect_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url, timeout=5)

        # Count redirects
        redirect_count = len(response.history)

        if redirect_count <= 1:
            return 1
        else:
            return 0

    except:
        return 0

def on_mouseover_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url, timeout=5)
        content = response.text.lower()

        # Check for suspicious onmouseover behavior
        if "onmouseover" in content:
            return -1
        else:
            return 1

    except:
        return -1

def right_click_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url, timeout=5)
        content = response.text.lower()

        # Check for right-click disable script
        if "event.button==2" in content or "contextmenu" in content:
            return -1
        else:
            return 1

    except:
        return -1

def popup_window_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url, timeout=5)
        content = response.text.lower()

        # Check for popup-related JavaScript
        if "alert(" in content or "prompt(" in content or "confirm(" in content:
            return -1
        else:
            return 1

    except:
        return -1

def iframe_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        iframes = soup.find_all("iframe")

        for iframe in iframes:
            # Check for hidden iframe
            if iframe.get("frameborder") == "0" or iframe.get("width") == "0" or iframe.get("height") == "0":
                return -1

        if len(iframes) > 0:
            return -1  # iframe exists → suspicious

        return 1

    except:
        return -1

def age_of_domain_feature(url):
    try:
        domain = urlparse(url).netloc

        # Remove 'www.'
        if domain.startswith("www."):
            domain = domain[4:]

        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        # Handle list format
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return -1

        # Calculate age
        today = datetime.now()
        age_days = (today - creation_date).days

        if age_days >= 180:
            return 1
        else:
            return -1

    except:
        return -1

def dns_record_feature(url):
    try:
        domain = urlparse(url).netloc

        # Remove 'www.'
        if domain.startswith("www."):
            domain = domain[4:]

        # Try resolving domain
        socket.gethostbyname(domain)

        return 1  # DNS exists

    except:
        return -1  # No DNS

def web_traffic_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url, timeout=5)

        # If site is reachable → assume some traffic
        if response.status_code == 200:
            return 0  # Suspicious (unknown traffic)
        else:
            return -1

    except:
        return -1

def page_rank_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            return 1  # assume some authority
        else:
            return -1

    except:
        return -1

def google_index_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Search in Google
        query = "https://www.google.com/search?q=site:" + url
        response = requests.get(query, timeout=5)

        # If results found → indexed
        if "did not match any documents" in response.text.lower():
            return -1
        else:
            return 1

    except:
        return -1

def links_pointing_to_page_feature(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        domain = urlparse(url).netloc

        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        anchors = soup.find_all('a')

        count = 0

        for tag in anchors:
            href = tag.get('href')
            if href and domain in href:
                count += 1

        # Apply rule
        if count == 0:
            return -1
        elif count <= 2:
            return 0
        else:
            return 1

    except:
        return -1

def statistical_report_feature(url):
    try:
        domain = urlparse(url).netloc

        # Example blacklist (can expand)
        phishing_domains = [
            "phishing.com",
            "malicious.com",
            "badsite.com"
        ]

        # Check domain
        for bad in phishing_domains:
            if bad in domain:
                return -1

        # Check IP pattern (known bad IP ranges example)
        if re.search(r'192\.168\.', domain):
            return -1

        return 1

    except:
        return -1

def predict_url(url):
    features = []

    # Address bar features
    features.append(having_ip_address(url))
    features.append(url_length_feature(url))
    features.append(shortening_service_feature(url))
    features.append(having_at_symbol_feature(url))
    features.append(double_slash_redirecting_feature(url))
    features.append(prefix_suffix_feature(url))
    features.append(having_sub_domain_feature(url))
    features.append(sslfinal_state_feature(url))
    features.append(domain_registration_length_feature(url))
    features.append(favicon_feature(url))
    features.append(port_feature(url))
    features.append(https_token_feature(url))

    # Abnormal features
    features.append(request_url_feature(url))
    features.append(url_of_anchor_feature(url))
    features.append(links_in_tags_feature(url))
    features.append(sfh_feature(url))
    features.append(submitting_to_email_feature(url))
    features.append(abnormal_url_feature(url))

    # HTML & JS features
    features.append(redirect_feature(url))
    features.append(on_mouseover_feature(url))
    features.append(right_click_feature(url))
    features.append(popup_window_feature(url))
    features.append(iframe_feature(url))

    # Domain features
    features.append(age_of_domain_feature(url))
    features.append(dns_record_feature(url))
    features.append(web_traffic_feature(url))
    features.append(page_rank_feature(url))
    features.append(google_index_feature(url))
    features.append(links_pointing_to_page_feature(url))
    features.append(statistical_report_feature(url))

    features_df = pd.DataFrame([features], columns=columns)

    prediction = model.predict(features_df)[0]

    if prediction == 1:
        return "Legitimate Website"
    else:
        return "Phishing Website"
    
url = input("Enter URL: ")
print("Prediction:", predict_url(url))  
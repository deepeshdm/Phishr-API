
import math
import string
import socket
import os
from urllib.parse import urlparse
from urllib.parse import urlparse
import requests
import csv
from whois import whois
from datetime import datetime
from bs4 import BeautifulSoup
from Known_Sites import TEMPORARY_DOMAIN_PLATFORMS

# Check if URL is https
def is_https(url):
    return url.startswith('https')


# Check if given URL is present in list of valid URLs
def check_top1million_database(url):
    with open('top-1million-sites.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if url in row[1] or url in "https://www."+row[1]:
                print(f"{url} is in the top 1 million websites according to Alexa.")
                return True
        print(f"{url} is not in the top 1 million websites according to Alexa.")
        return False


# Check if URL is temporarily registered subdomain
def is_temporary_domain(url):
    for temp_domain in TEMPORARY_DOMAIN_PLATFORMS:
        if temp_domain in url:
            return True
    return False


# Get domain registrar's name
def get_registrar(url):
    try:
        w = whois(url)
        registrar = w.registrar
        return registrar
    except Exception as e:
        print(f"Error: {e}")
        return None


# Check if given domain is X months old
def get_days_since_creation(domain, months):
    try:
        w = whois(domain)
        creation_date = w.creation_date
        if type(creation_date) == list:
            creation_date = creation_date[0]
        days_since_creation = (datetime.now() - creation_date).days
        months_since_creation = days_since_creation / 30
        return months_since_creation >= months
    except Exception as e:
        print("Unable to access Registeration date for Domain !")
        return None


# Check the Mcafee database for URL safety
def check_mcafee_database(url):
    mcafee_url = f"https://www.siteadvisor.com/sitereport.html?url={url}"
    response = requests.get(mcafee_url)

    if response.status_code == 200:
        if "is safe" in response.text:
            print(f"{url} is safe to visit according to McAfee SiteAdvisor.")
            return True
        else:
            print(f"{url} may be dangerous according to McAfee SiteAdvisor. Please proceed with caution.")
            return False
    else:
        print("Unable to check URL against McAfee SiteAdvisor database.")
        return False


# Check Google's Database for Malicious sites
# NOTE: Gives false for dynamic sites like Twitter, Youtube etc since their content can't be analysed.
def check_google_safe_browsing(url):
    google_url = f"https://transparencyreport.google.com/safe-browsing/search?url={url}"
    response = requests.get(google_url)

    if response.status_code == 200:
        if "No unsafe content found" in response.text:
            print(f"{url} is safe to visit according to Google Safe Browsing.")
            return True
        else:
            print(f"{url} may be dangerous according to Google Safe Browsing. Please proceed with caution.")
            return False
    else:
        print("Unable to check URL against Google Safe Browsing database.")
        return False


# Returns True if url in blacklist
def checkLocalBlacklist(url):
    # path to blacklisted sites file
    dataset = "blacklisted_sites.txt"
    with open(dataset, 'r') as file:
        for line in file:
            website = line.strip()
            if url == website:
                return True
    return False

def checkSucuriBlacklists(url):
    # Construct the URL for sitecheck.sucuri.net
    check_url = f"https://sitecheck.sucuri.net/results/{url}"

    # Make the HTTP GET request
    response = requests.get(check_url)

    # Check if "Site is not Blacklisted" is present in the response body
    if "Site is not Blacklisted" in response.text:
        print(f"{url} is safe to visit according to Sucuri Blacklists.")
        return True
    else:
        print(f"{url} is NOT safe to visit according to Sucuri Blacklists.")
        return False


# scan UrlVoid's 40 blacklist sources and return 
# the number of sources url matched during scanning
def checkURLVoid(url):
    try:
        # Construct the URL for urlvoid.com
        scan_url = f"https://www.urlvoid.com/scan/{url}"

        # Make the HTTP GET request
        response = requests.get(scan_url)

        # Parse the response content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find the span tag with class "label label-danger"
        span_tag = soup.find('span', class_="label label-danger")

        # Extract and return the value before the '/'
        if span_tag:
            label_text = span_tag.get_text().strip()
            return int(label_text.split('/')[0])
        else:
            return 0
    except:
       return 0

#---------------------------------------------------------------------------------------

# AI model helpers

def get_domain_length(url):
    """
    Returns the length of the entire URL.
    """
    return len(url)


def get_domain_entropy(url):
    """
    Returns the entropy of the domain name.
    """
    domain = urlparse(url).netloc
    alphabet = string.ascii_lowercase + string.digits
    freq = [0] * len(alphabet)
    for char in domain:
        if char in alphabet:
            freq[alphabet.index(char)] += 1
    entropy = 0
    for count in freq:
        if count > 0:
            freq_ratio = float(count) / len(domain)
            entropy -= freq_ratio * math.log(freq_ratio, 2)
    return round(entropy,2)


def is_ip_address(url):
    """
    Returns True if the URL uses an IP address instead of a domain name.
    """
    domain = urlparse(url).netloc
    try:
        socket.inet_aton(domain)
        return 1
    except socket.error:
        return 0


def has_malicious_extension(url):
    _, ext = os.path.splitext(url)
    malicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.js', '.vbs', 
                            '.hta', '.ps1', '.jar', '.py', '.rb']
    
    if ext.lower() in malicious_extensions:
        return 1
    else:
        return 0


def query_params_count(url):
    """
    Returns Number of query parameters in the URL
    """
    parsed = urlparse(url)
    query_params = parsed.query.split('&')
    if query_params[0] == '':
        return 0
    else:
        return len(query_params)


def path_tokens_count(url):
    """
    Returns Number of path tokens
    """
    parsed = urlparse(url)
    path_tokens = parsed.path.split('/')
    path_tokens = [token for token in path_tokens if token]  # remove empty tokens
    return len(path_tokens)


def hyphens_count(url):
    """
    Returns the number of hyphens in the entire URL
    """
    parsed = urlparse(url)
    return url.count('-')


def digits_count(url):
    """
    Returns Number of digits in the entire URL
    """
    return sum(c.isdigit() for c in url)


def has_special_characters(url):
    special_chars = ['@', '!', '#', '$', '%', '^', '&', '*', '_', '+']
    for char in special_chars:
        if char in url:
            return 1
    return 0


def getInputArray(url):
    result = []
    result.append(get_domain_length(url))
    result.append(get_domain_entropy(url))
    result.append(is_ip_address(url))
    result.append(has_malicious_extension(url))
    result.append(query_params_count(url))
    result.append(path_tokens_count(url))
    result.append(hyphens_count(url))
    result.append(digits_count(url))
    result.append(has_special_characters(url))
    return result

# Load the model and make prediction
# Returns 1 if malicious else 0
def isURLMalicious(url,clf):
    input = getInputArray(url)
    # make predictions on the new data
    prediction = clf.predict([input])[0]
    return prediction



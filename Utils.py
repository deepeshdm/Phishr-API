
import math
import string
import socket
import os
import ipaddress
import Levenshtein
import traceback
from ail_typo_squatting import runAll
import math
from tqdm import tqdm
from urllib.parse import urlparse
import requests
import csv
from ssl_checker import SSLChecker
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from Known_Sites import TEMPORARY_DOMAIN_PLATFORMS
import firebase_admin
from firebase_admin import firestore
from firebase_admin import credentials

# Firebase Private Key
PRIVATE_KEY_PATH = "firebase/phishr-d74a9-firebase-adminsdk-vcpiv-0328924687.json"
cred = credentials.Certificate(PRIVATE_KEY_PATH)
firebase_admin.initialize_app(cred)
# Create a Firestore client
db = firestore.client()

# ------------------------------------------------------

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


# Extracts the main domain and matches it
def check_top1million_database_2(url):
    # Extract the domain from the URL
    domain = urlparse(url).netloc
    if not domain:
        domain = url.split('/')[0]
    with open('top-1million-sites.csv', 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if domain == row[1] or domain == "www."+row[1]:
                print(
                    f"{domain} is in the top 1 million websites according to Alexa.")
                return True
        print(f"{domain} is not in the top 1 million websites according to Alexa.")
        return False


# Check if a URL has SSL certificate (https://github.com/narbehaj/ssl-checker)
def check_ssl_certificate(url):
    try:
        ssl_checker = SSLChecker()
        args = {'hosts': [url]}
        output = ssl_checker.show_result(ssl_checker.get_args(json_args=args))
        if "cert_valid" in output:
            return True
        else:
            return False
    except:
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
        w = whois.whois(url)
        registrar = w.registrar
        return registrar
    except Exception as e:
        print(f"Error: {e}")
        return None

# ---------------------------------------------------------------------------------------

# Check if given domain is X months old
def get_days_since_creation(domain, months):
    try:
        w = whois.whois(domain)
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
            print(
                f"{url} may be dangerous according to McAfee SiteAdvisor. Please proceed with caution.")
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
            print(
                f"{url} may be dangerous according to Google Safe Browsing. Please proceed with caution.")
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

# Check if Valid IPV4 or V6 address
def is_valid_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# Returns True if IP is BlackList in Local Ipsets
def check_ip_in_ipsets(ip):
    # Convert IP address string to an IP object
    ip_address = ipaddress.ip_address(ip)

    # Directory path where IPset files are located
    ipset_directory = "blocklist-ipsets/IpSets"

    # Iterate over the files in the IPset directory with a progress bar
    for root, dirs, files in os.walk(ipset_directory):
        for file in tqdm(files, desc="Checking IPset files"):
            # Construct the full path of the IPset file
            ipset_file = os.path.join(root, file)

            # Open the IPset file for reading
            with open(ipset_file, 'r') as file:
                # Iterate over each line in the IPset file
                for line in file:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        try:
                            # Parse the line as an IP network
                            subnet = ipaddress.ip_network(line)
                            # Check if the IP address is present in the IP network
                            if ip_address in subnet:
                                return True
                        except ValueError:
                            # Ignore invalid IP networks
                            pass

    # The IP address was not found in any IPset file
    return False


def checkSucuriBlacklists(url):
    # Construct the URL for sitecheck.sucuri.net
    check_url = f"https://sitecheck.sucuri.net/results/{url}"

    # Make the HTTP GET request
    response = requests.get(check_url)

    # Check if "Site is Blacklisted" is present in the response body
    if "Site is Blacklisted" in response.text:
        print(f"{url} is NOT safe to visit according to Sucuri Blacklists.")
        return False
    else:
        print(f"{url} is safe to visit according to Sucuri Blacklists.")
        return True


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

# Returns false if URL is considered malicious
def check_Nortan_WebSafe(url):
    try:
        response = requests.get(
            f"https://safeweb.norton.com/report/show?url={url}")
        html_content = response.text
        if "known dangerous webpage" in html_content:
            print("The URL is NOT safe as per Nortan Safe Web !")
            return False
        else:
            print("The URL is safe as per Nortan Safe Web !")
            return True
    except Exception:
        return True


# ---------------------------------------------------------------------------------------

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
    return round(entropy, 2)


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
    # remove empty tokens
    path_tokens = [token for token in path_tokens if token]
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


def isURLMalicious(url, clf):
    input = getInputArray(url)
    # make predictions on the new data
    prediction = clf.predict([input])[0]
    return prediction

# ---------------------------------------------------------------------------------------

# Returns 0-10 similarity score between 2 URLs


def calculate_url_similarity(url1, url2):
    levenshtein_distance = Levenshtein.distance(url1, url2)
    similarity_score = (1 - levenshtein_distance /
                        max(len(url1), len(url2))) * 10
    return similarity_score


# Extract the domain name from URL
def strip_url(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not domain:
        # If the domain is empty, it could be a case of a bare domain
        domain = parsed_url.path.strip("/")
    if not domain.startswith("www."):
        domain = domain.lstrip("www.")
    return domain


# Takes a domain name and returns array of similar urls
# NOTE: Only works for domain names in the format like "google.com" or "www.apple.in"
# Source : https://ail-project.github.io/ail-typo-squatting/
def generate_similar_urls(url, max_urls=5000):
    resultList = list()
    pathOutput = "./type-squating-data/"
    formatoutput = "text"

    # Run the ail_typo_squatting module to generate similar URLs
    resultList = runAll(
        domain=url,
        limit=math.inf,
        pathOutput=pathOutput,
        formatoutput=formatoutput,
        verbose=False,
        givevariations=False,
        keeporiginal=False
    )

    similar_urls = []
    if resultList is not None:
        # Iterate over all the generated similar URLs
        for modifiedUrl in resultList:
            # Only choose URLs with certain similarity score
            if calculate_url_similarity(url, modifiedUrl) > 5:
                similar_urls.append(modifiedUrl)

            # Only keep desired number of similar URLs
            if len(similar_urls) >= max_urls:
                return similar_urls
    return similar_urls


# Takes a TypeSquated URL and Find its Targeted URL
def find_target_urls(fake_url, similarity_score=7):
    fake_url = str(fake_url).lower()
    similar_urls = []
    # Extract the domain from the URL
    domain = urlparse(fake_url).netloc
    if not domain:
        domain = fake_url.split('/')[0]
    with open('top-1million-sites.csv', 'r') as f:
        reader = csv.reader(f)
        print("Finding target URL...")
        # Iterate over all domains
        for row in reader:
            # Find similarity between fake_url & valid domain
            if calculate_url_similarity(domain, row[1]) > similarity_score:
                similar_urls.append(row[1])
        return similar_urls

# ---------------------------------------------------------------------------------------


def convert_datetime_list_to_string(date_list):
    formatted_strings = []
    for dt in date_list:
        if isinstance(dt, datetime):
            formatted_string = "{:%d %B %Y, %H:%M:%S}".format(dt)
            formatted_strings.append(formatted_string)
        else:
            formatted_strings.append(str(dt))
    return formatted_strings


def array2String(someList):
    output = ""
    for i in someList:
        output = output + str(i) + " , "
    return output

# Checks if a domain is active & registered
def check_domain_registration(domain):
    # strip the url and extract domain
    domain = strip_url(domain)
    try:
        w = whois.whois(domain)
        if w.status:
            return w
        else:
            return None
    except Exception as e:
        print("Error occcured in check_domain_registration() !")
        print("ERROR : ",str(e))  # Print the error message from the exception
        traceback.print_exc()  # Print the full traceback
        return None


# Extract only information we need from each domain details
def process_domain_details(registered_urls):

    AlldomainDetails = []

    for domainDetails in registered_urls:

        registrar = domainDetails["registrar"]

        domain_name = domainDetails["domain_name"]
        if isinstance(domain_name, list):
            domain_name = domain_name[0]

        country = domainDetails["country"]
        if isinstance(country, list):
            country = array2String(country)
        domainDetails["country"] = country

        creation_date = domainDetails["creation_date"]
        if isinstance(creation_date, list):
            creation_date = convert_datetime_list_to_string(creation_date)
            creation_date = creation_date[0]
        else:
            creation_date = "{:%d %B %Y, %H:%M:%S}".format(creation_date)
        domainDetails["creation_date"] = creation_date

        name_servers = domainDetails["name_servers"]
        if isinstance(name_servers, list):
            name_servers = array2String(name_servers)
        domainDetails["name_servers"] = name_servers

        output = {
            "registrar": registrar,
            "domain_name": str(domain_name).upper(),
            "country": country,
            "creation_date": creation_date,
            "name_servers": name_servers,
            "status": "VERIFIED ✅"
        }

        AlldomainDetails.append(output)

    return AlldomainDetails


# Takes a list of urls and returns list in output format
# NOTE : We only keep 500 Urls
def process_unregistered_urls(unregistered_urls):

    urls = []

    for url in unregistered_urls:

        if len(urls) >= 500:
            break

        output = {
            "registrar": None,
            "domain_name": url,
            "country":  None,
            "creation_date":  None,
            "name_servers":  None,
            "status":  "UNVERIFIED ✖️",
        }

        output["domain_name"] = str(url).upper()
        urls.append(output)

    return urls


# Returns details of similar looking ACTIVE REGISTERED domains
# Returns False if domain is Invalid.
def registered_similar_domains(domain, max_urls=20):

    if check_domain_registration(domain) == None:
        # Check if domain is present in Top 1 Million sites
        if check_top1million_database(domain) or check_top1million_database_2(domain):
            print("Domain in Top 1 Million Sites !")
        else:
             # If domain is inactive return false
            return False

    output = {
        "unregistered_urls": None,  # array of similar urls (unregistered)
        "registered_urls": None,   # array of registered domain details
        "total_permutations": None,
    }

    # strip the url and extract domain
    domain = strip_url(domain)
    original_domain = domain
    print("Stripped Domain : ", domain)

    # generate similar looking
    similar_urls = generate_similar_urls(domain)
    output["total_permutations"] = len(similar_urls)
    print("Total Similar URLs : ", len(similar_urls))

    urls = []  # list of all registered domains details
    stopper = 0
    for domain in similar_urls:

        if domain==original_domain:
            continue

        if stopper >= 20:
            # stop loop if no registered domain found after 20 continuous iterations
            print("No registered domain found for 20 iterations ! Stopping Loop. ")
            break

        if len(urls) >= max_urls:
            output["unregistered_urls"] = similar_urls
            output["registered_urls"] = urls
            return output

        # Check domain registration details and save it
        registration_details = check_domain_registration(domain)
        if registration_details:
            print(f"The domain '{domain}' is active and registered.")
            stopper = 0
            urls.append(registration_details)
        else:
            stopper = stopper + 1
            # remove the registered domain from list of urls
            similar_urls = [x for x in similar_urls if x != domain]
            print(f"The domain '{domain}' is not registered or inactive.")

    output["unregistered_urls"] = similar_urls
    output["registered_urls"] = urls
    return output



# Takes a valid domain as Input and returns collection of 
# registered and unregistered typosquatted domains
def getTypoSquattedDomains(domain,max_num=20):

    output = registered_similar_domains(domain, max_num)

     # If domain is inactive return false
    if output==False:
        return False

    total_permutations = output["total_permutations"]
    registered_urls = output["registered_urls"]
    unregistered_urls = output["unregistered_urls"]

    # process the results
    registered_urls = process_domain_details(registered_urls)
    unregistered_urls = process_unregistered_urls(unregistered_urls)
    allDomains = registered_urls + unregistered_urls

    result = {
        "total_permutations": total_permutations,
        "allDomains": allDomains
    }

    return result

# ---------------------------------------------------------------------------------------

# Check if URL exists in 'Reported_Urls' & 'Bulk_Reported_Urls' collections
def url_in_reporting_database(url):

    # Check "Reported_Urls" collection
    reported_urls_query = db.collection(
        'Reported_Urls').where("Url", "==", url)
    reported_urls_docs = reported_urls_query.stream()

    # Check "Bulk_Reported_Urls" collection
    bulk_reported_urls_query = db.collection(
        'Bulk_Reported_Urls').where("Url", "==", url)
    bulk_reported_urls_docs = bulk_reported_urls_query.stream()

    # Check if any matching documents exist in "Reported_Urls" collection
    if len(list(reported_urls_docs)) > 0:
        return True

    # Check if any matching documents exist in "Bulk_Reported_Urls" collection
    if len(list(bulk_reported_urls_docs)) > 0:
        return True

    return False

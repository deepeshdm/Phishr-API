
import requests
import csv
from whois import whois
from datetime import datetime
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




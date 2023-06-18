
import Utils

# Returns score (0-180) , 0 is malicious 100 is safest site
def get_prediction(url, model):

    output = {
        "SCORE": 180,
        "InTop1Million": False,
        "InURLVoidBlackList": False,
        "isHTTPS": True,
        "hasSSLCertificate": True,
        "GoogleSafePassed": True,
        "NortanWebSafePassed": True,
        "InMcaffeBlackList": False,
        "InSucuriBlacklist": False,
        "isTemporaryDomain": False,
        "isOlderThan3Months": True,
        "isBlackListedinIpSets": False,
        "target_urls": None
    }

    # -------------------------------------------------

    try:
        # Finding Possible Target URLs
        print("Finding Target URLs...")
        target_urls = Utils.find_target_urls(url, 8)
        output["target_urls"] = target_urls
    except:
        print("Error Occured while finding target Urls !")

    # ------------------------------------------------------

    # Check Top 1 million valid sites
    if Utils.check_top1million_database(url):
        output["InTop1Million"] = True

    # Check the domain in Top 1 million valid sites
    if Utils.check_top1million_database_2(url):
        output["InTop1Million"] = True

    if output["InTop1Million"] == True:
        # If URL is already valid no need to check further.
        return output

    # Check 40 blacklist sources
    if Utils.checkURLVoid(url) > 0:
        output["SCORE"] = output["SCORE"] - 20
        output["InURLVoidBlackList"] = True
        print("URL is blacklisted in UrlVoid's system !")
    else:
        print("URL is Safe in UrlVoid's system !")

    # Check if it has SSL certififcate
    if Utils.check_ssl_certificate(url) != True:
        output["hasSSLCertificate"] = False
        print("URL has not SSL Certificate !")
        output["SCORE"] = output["SCORE"] - 20

    # Check if HTTP/HTTPS. # If SSL present then it's already HTTPS safe
    if output["hasSSLCertificate"] != True and Utils.is_https(url) != True:
        print("URL is not HTTP secure")
        output["isHTTPS"] = False

    if Utils.check_google_safe_browsing(url) != True:
        output["GoogleSafePassed"] = False
        output["SCORE"] = output["SCORE"] - 20

    if Utils.check_Nortan_WebSafe(url) != True:
        output["NortanWebSafePassed"] = False
        output["SCORE"] = output["SCORE"] - 20

    if Utils.check_mcafee_database(url) != True:
        output["InMcaffeBlackList"] = True
        output["SCORE"] = output["SCORE"] - 10

    if Utils.checkSucuriBlacklists(url) != True:
        output["InSucuriBlacklist"] = True
        output["SCORE"] = output["SCORE"] - 10

    if Utils.is_temporary_domain(url):
        print("Domain is registered from unsecure source")
        output["isTemporaryDomain"] = True
        output["SCORE"] = output["SCORE"] - 10

    # check if url is older than 3 months
    if Utils.get_days_since_creation(url, 3) != True:
        print("Domain is less than 3 months old")
        output["isOlderThan3Months"] = False
        output["SCORE"] = output["SCORE"] - 10

    if Utils.checkLocalBlacklist(url):
        print("The URL is blacklisted !")
        output["SCORE"] = output["SCORE"] - 20

    if Utils.is_valid_ip(url) == True:
        if Utils.check_ip_in_ipsets(url):
            print("The IP address is blacklisted !")
            output["isBlackListedinIpSets"] = True
            output["SCORE"] = output["SCORE"] - 20
    else:
        print("Given address is not an valid IP address !")

    # Make prediction using AI model
    if Utils.isURLMalicious(url, model) == 1:
        print("Model predicted the URL as malicious")
        output["SCORE"] = output["SCORE"] - 20
    else:
        print("Model predicted URL not malicious !")

    # Check if URL is present in Reporting database
    if Utils.url_in_reporting_database(url):
        print("URL is also present in the Reporting database !")
        output["SCORE"] = output["SCORE"] - 20
    else:
        print("URL not in Reporting Database !")

    return output

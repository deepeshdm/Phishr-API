
import Utils

# Returns score (0-100) , 0 is malicious 100 is safest site
def get_prediction(url, model):

    SCORE = 130

    # Check Top 1 million valid sites
    if Utils.check_top1million_database(url) : 
        return SCORE
    
    # Check the domain in Top 1 million valid sites
    if Utils.check_top1million_database_2(url) : 
        return SCORE
    
    # Check 40 blacklist sources
    if Utils.checkURLVoid(url)>0:
        print("URL is blacklisted in UrlVoid's system !")
        return 0
    else:
        print("URL is Safe in UrlVoid's system !")

    # Check if HTTP/HTTPS
    if Utils.is_https(url)!=True:
        print("URL is not HTTP secure")
        SCORE = SCORE - 10

    if Utils.check_google_safe_browsing(url)!=True:
        SCORE = SCORE - 20

    if Utils.check_Nortan_WebSafe(url)!=True:
        SCORE = SCORE - 20
    
    if Utils.check_mcafee_database(url)!=True:
        SCORE = SCORE - 10

    if Utils.checkSucuriBlacklists(url)!=True:
        SCORE = SCORE - 10

    if Utils.is_temporary_domain(url):
        print("Domain is registered from unsecure source")
        SCORE = SCORE - 10

    # check if url is older than 3 months
    if Utils.get_days_since_creation(url,3)!=True:
        print("Domain is less than 3 months old")
        SCORE = SCORE - 10

    if Utils.checkLocalBlacklist(url):
        print("The URL is blacklisted !")
        SCORE = SCORE - 20
    
    # Make prediction using AI model
    if Utils.isURLMalicious(url,model)==1:
        print("Model predicted the URL as malicious")
        SCORE = SCORE - 20

    return SCORE
    


import Utils

# Returns score (0-100) , 0 is malicious 100 is safest site
def get_prediction(url, model_path):

    SCORE = 100

    # Check Top 1 million valid sites
    if Utils.check_top1million_database(url) : 
        return SCORE

    # Check if HTTP/HTTPS
    if Utils.is_https(url)!=True:
        print("URL is not HTTP secure")
        SCORE = SCORE - 20

    if Utils.check_google_safe_browsing(url)!=True:
        SCORE = SCORE - 20
    
    if Utils.check_mcafee_database(url)!=True:
        SCORE = SCORE - 20

    if Utils.is_temporary_domain(url):
        print("Domain is registered from unsecure source")
        SCORE = SCORE - 20

    # check if url is older than 3 months
    if Utils.get_days_since_creation(url,3)!=True:
        print("Domain is less than 3 months old")
        SCORE = SCORE - 20

    return SCORE
    

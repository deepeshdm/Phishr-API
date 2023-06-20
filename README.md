# Phishr Rest-API

### A Rest API for 'Phishr' - A Cybersecurity utility for detecting malicious Urls

<div align="center">
<Img width="85%" src="/docs.png"/>
</div>

## API Guide
This API is designed to detect potentially malicious URLs. It takes a URL as an input and scans it. The detection process involves several steps, including checking against various databases, verifying SSL certificates, and utilizing an AI model for prediction. It provides detailed information about the URL's status and flags potential risks.

✅ Below is the API response for "www.google.com", which is a safe website.
```
 "prediction": {
    "SCORE": 180,
    "InTop1Million": true,
    "InURLVoidBlackList": false,
    "isHTTPS": true,
    "hasSSLCertificate": true,
    "GoogleSafePassed": true,
    "NortanWebSafePassed": true,
    "InMcaffeBlackList": false,
    "InSucuriBlacklist": false,
    "isTemporaryDomain": false,
    "isOlderThan3Months": true,
    "isBlackListedinIpSets": false,
    "target_urls": []
  }
```

❌ Below is the API response for an Malicious URL.
```
 "prediction": {
    "SCORE": 50,
    "InTop1Million": false,
    "InURLVoidBlackList": false,
    "isHTTPS": false,
    "hasSSLCertificate": false,
    "GoogleSafePassed": false,
    "NortanWebSafePassed": true,
    "InMcaffeBlackList": true,
    "InSucuriBlacklist": true,
    "isTemporaryDomain": false,
    "isOlderThan3Months": false,
    "isBlackListedinIpSets": false,
    "target_urls": []
  }
```

NOTE : It is a scoring-based system where the URL is first assigned the highest score of 180, which is reduced at every detection step that it fails. The safest site would have a score close to 180, whereas the malicious URLs will have a score close to 0.

- Checkout the API documentation - [here](phishr-api.up.railway.app/docs) 
- React Web Interface repository - [here](https://github.com/deepeshdm/phishr)
- Model Training repository - [here](https://github.com/deepeshdm/Phishing-Attack-Domain-Detection)


## To Run (Locally)

1. Git clone the project repository on your local system
```
git clone https://github.com/deepeshdm/Phishr-API.git
```

2. Install dependencies in requirements.txt
```
pip install -r requirements.txt
```

3. Create a new Firebase project and setup a Firestore database. Generate a private key file through the Firebase console and place it inside "/firebase" directory. If you already have Firestore setup for Frontend then use the same project to generate private key file.
```
{
  "type": "service_account",
  "project_id": "XXXXXXXXXXX",
  "private_key_id": "XXXXXXXXXXXX",
  "private_key": "XXXXXXXXXXXXX",
  "client_email": "XXXXXXXXXXXXXXXXXX",
  "client_id": "XXXXXXXXXXXXXXXX",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "XXXXXXXXXXXX",
  "universe_domain": "googleapis.com"
}
```
4. Start the FastAPI server on localhost & then Visit "http://localhost:8000/docs" to check endpoints.
```
python app.py
```

References :
 - https://www.kaggle.com/datasets/cheedcheed/top1m
 - https://github.com/firehol/blocklist-ipsets
 - https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset
 - https://github.com/narbehaj/ssl-checker



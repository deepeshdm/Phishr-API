
import json
import uvicorn
import pickle
from fastapi import FastAPI
from UrlData import UrlData, DomainData
from Utils import getTypoSquattedDomains
from API import get_prediction
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(debug=True)

# ------------------------------------------

# Enabling CORS policy

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------

# load the LightGBM classifier using pickle
print("Loading the model...")
with open('lightgbm_classifier.pkl', 'rb') as file:
    clf = pickle.load(file)


@app.post("/predict")
def predict(data: UrlData):

    # convert to dictionary
    data = data.dict()

    # the key has same name as you put in class
    url = data["url"]

    # predict price using ML model
    prediction = get_prediction(url, clf)
    print("Predicted Probability : ", prediction)

    # always return the output as dictionary/json.
    prediction = {"prediction": prediction}

    return prediction


@app.post("/get_typesquatted_urls")
def get_similar_urls(data: DomainData):

    # convert to dictionary
    data = data.dict()

    # the key has same name as you put in class
    url = data["url"]
    max_num = data["max_num"]

    if (max_num <= 0):
        max_num = 20

    # result
    output = getTypoSquattedDomains(url, max_num)
    print("API OUTPUT : ", output)
    output = {"output": output}

    # Convert the output dictionary to JSON-compatible format
    output_dict = json.loads(json.dumps(output, default=str))
    return output_dict




if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)

    # changed 127.0.0.1 to 0.0.0.0 for railway.app deployment

    # you can go to "/docs" or "/redoc" endpoint to get the API documentation

    # command to run in terminal in order to start the app
    # ==> uvicorn app:app --reload

    # Make sure to run the above command from the same directory
    # where the app file is present

    # Wait until you get the below message in terminal :
    # "Application startup complete".

# NOTE : CLI command for deployment on Railway "uvicorn app:app --host 0.0.0.0 --port $PORT"
# NOTE : On Railway app we provide the port as $PORT, the port is provided by railway cloud.

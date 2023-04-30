

import uvicorn
from fastapi import FastAPI
from UrlData import UrlData
from API import get_prediction
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

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

model_path = r"Malicious_URL_Prediction.h5"

# passing variables to ML model to return prediction
# NOTE : the request is POST
@app.post("/predict")
def predict(data: UrlData):

    # convert to dictionary
    data = data.dict()

    # the key has same name as you put in HouseData class
    url = data["url"]


    # predict price
    prediction = get_prediction(url,model_path)
    print("Predicted Probability : ",prediction)

    # always return the output as dictionary/json.
    # It's better if your output is a string.
    prediction = {"prediction": str(prediction)}

    return prediction


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






















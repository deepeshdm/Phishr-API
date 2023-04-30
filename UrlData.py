

from pydantic import BaseModel

class UrlData(BaseModel):
    """
    define your variables here with same name
    that you want your user to see.
    """

    url : str



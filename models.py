from pydantic import BaseModel

class User(BaseModel):
    user_name: str
    user_fullName: str
    user_email: str
    user_add: str
    user_pass: str
    access_token: str = ""
    refresh_token: str = ""


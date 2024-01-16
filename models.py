from pydantic import BaseModel

class User(BaseModel):
    user_id: int
    user_name : str
    user_fullName : str
    user_email : str
    user_add : str

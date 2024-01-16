from fastapi import FastAPI
from models import User

app = FastAPI()
user_list : dict[int,User] = {}

@app.get("/")
def root():
    return {"message" : "Hi there"}

# @app.post("/register/{user_name}/{user_pass}")
# def registerUser(user_name:str,user_pass:int):
#     user_ids = {user.user_name : user.user_id 
#                 for user in user_list.values()}

#     if user_name in user_ids.keys():
#         user_id = user_ids[user_name]
#         # return {"message" : "User Already Exist"}
#     else:
#         # user_id = max(user_ids.keys()) + 1 if user_list else 0


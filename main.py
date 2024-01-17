from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
import json
import re
from typing import Optional
import bcrypt
from jose import jwt


app = FastAPI()

users = {}

SECRET_KEY = "javainuse-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY_MINUTES = 30
REFRESH_TOKEN_EXPIRY_DAYS = 7


def generate_access_token(data: dict, expires_delta: int = 0):
    user_data = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + timedelta(minutes=expires_delta)
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    user_data.update({"expiry": expire.isoformat()})
    encoded_jwt = jwt.encode(user_data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def generate_refresh_token(data: dict):
    return generate_access_token(data, expires_delta=REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60)


def refresh_access_token(refresh_token):
    decoded_refresh_token = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    username = decoded_refresh_token['data']

    if users.get(username, {}).get('refresh_token') != refresh_token:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    access_token_data = {"data": username}
    new_access_token = generate_access_token(access_token_data)
    users[username]['access_token'] = new_access_token
    save_to_json(users)

    return new_access_token


with open("output.json", "r") as json_file:
        users = json.load(json_file)


@app.get("/")
def root():
    return {"message" : "Helloo Adi"}


def save_to_json(data):
    with open("output.json", "w") as json_file:
        json.dump(data, json_file)
        json_file.write('\n') 


def is_valid_email(email):
    # Define a regular expression pattern for a simple email validation
    email_pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
    return bool(re.match(email_pattern, email))


@app.post("/create/user/")
def create_user(user_name: str, user_fullName: str, user_email: str, user_add: str ,user_pass : str):

    if user_name in users.keys() or any(u['user_email'] == user_email for u in users.values()):
        raise HTTPException(status_code=400, detail="User with duplicate user_name, or user_email already exists.")

    if not is_valid_email(user_email):
        raise HTTPException(status_code=422, detail="Email not Valid")

    if not 8 <= len(user_pass) <= 16:
        raise HTTPException(status_code=422, detail="Password short !!")

    #hashed_password = bcrypt.hash(user_pass)  # type: ignore
    hashed_password = bcrypt.hashpw(user_pass.encode('utf-8'), bcrypt.gensalt())

    new_user_details = {
        'user_fullName': user_fullName,
        'user_email': user_email,
        'user_add': user_add,
        'user_pass' : hashed_password.decode('utf-8')
    }
    
    new_user = {
        user_name:new_user_details
    }

    users[user_name] = new_user_details
    save_to_json(users)

    return {user_name: new_user}


@app.get("/get_all_users")
def get_all_users():
    return users


@app.get("/get_user/{user_name}")
def get_user(user_name: str):
    if user_name in users.keys():
        return {user_name: users[user_name]}
    raise HTTPException(status_code=404, detail="User not found")


@app.delete("/delete_user/{user_name}")
def delete_user(user_name : str):
    if user_name in users.keys():
        deleted_user = users.pop(user_name)
        save_to_json(users)
        #return {"message": f"User {user_name} deleted successfully", "deleted_user": deleted_user}
        return {"message": "user deleted"}
    raise HTTPException(status_code=404, detail="User not found")


@app.put("/update_user/{user_name}")
def update_user(
    user_name: str,
    user_fullName: str = "",
    user_email: str = "",
    user_add: str = "",
):
    if user_name not in users.keys():
        raise HTTPException(status_code=404, detail="User not found")

    user_details = users[user_name]

    if user_fullName != "":
        user_details['user_fullName'] = user_fullName
    if user_email != "" and is_valid_email(user_email):
        user_details['user_email'] = user_email
    if user_add != "":
        user_details['user_add'] = user_add

    save_to_json(users)

    return {"message": "User {user_name} updated successfully", "updated_user": users[user_name]}

    
@app.post("/login")
def login_user(user_name: str, user_pass: str):
    if user_name not in users:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    loggedUser = users[user_name]

    if not bcrypt.checkpw(user_pass.encode('utf-8'), loggedUser['user_pass'].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid passward")

     #access token
    access_token_data = {"data": user_name}
    access_token = generate_access_token(access_token_data)

    # refresh tokeen
    refresh_token_data = {"data": user_name}
    refresh_token = generate_refresh_token(refresh_token_data)
    users[user_name]['refresh_token'] = refresh_token
    users[user_name]['access_token'] = access_token
    save_to_json(users)

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer", "message": "Login succes"}


@app.post("/refresh-token")
def refreshAccessToken(user_name: str):
    user = users.get(user_name)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    refresh_token = user.get('refresh_token')
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not available")

    new_access_token = refresh_access_token(refresh_token)
    return {"new_access_token": new_access_token}

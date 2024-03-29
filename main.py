from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
import json
import re
from typing import Optional
import bcrypt
from jose import jwt
from models import User
from motor.motor_asyncio import AsyncIOMotorClient
from constants import MONGO_URI,DATABASE_NAME,COLLECTION_NAME,ACCESS_TOKEN_EXPIRY_MINUTES,ALGORITHM,REFRESH_TOKEN_EXPIRY_DAYS,SECRET_KEY
import logging
logging.basicConfig(level=logging.INFO)
from fastapi import Depends



app = FastAPI()


# MongoDB client
client = AsyncIOMotorClient(MONGO_URI)
database = client[DATABASE_NAME]
collection = database[COLLECTION_NAME]


def is_valid_email(email):
    email_pattern = re.compile(r"[^@]+@[^@]+\.[^@]+")
    return bool(re.match(email_pattern, email))

# @app.post("/create_user")
# async def create_user(user: User):

#     if await collection.count_documents({
#         "$or": [{"user_name": user.user_name}, {"user_email": user.user_email}]
#     }) > 0:
#         raise HTTPException(status_code=400, detail="User already exists.")

#     if not is_valid_email(user.user_email):
#         raise HTTPException(status_code=422, detail="Email not Valid")

#     if not 8 <= len(user.user_pass) <= 16:
#         raise HTTPException(status_code=422, detail="Password short !!")

#     hashed_password = bcrypt.hashpw(user.user_pass.encode('utf-8'), bcrypt.gensalt())

#     new_user_details = {
#         "user_name": user.user_name,
#         "user_fullName": user.user_fullName,
#         "user_email": user.user_email,
#         "user_add": user.user_add,
#         "user_pass": hashed_password.decode('utf-8'),
#         "role":user.role or "student"
#     }
#     await collection.insert_one(new_user_details)

#     return {"message": "User created successfully"}




# async def get_users():
#     users = await collection.find({}).to_list(length=None)
#     for user in users:
#         user["_id"] = str(user["_id"])
#     return users

# @app.get("/get_all_users")
# async def get_all_users():
#     users = await get_users()
#     return users




# @app.get("/get_user/{user_name}")
# async def read_user(user_name: str):
#     user = await get_user(user_name)    
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found")
#     return user




# @app.delete("/delete_user/{user_name}")
# async def delete_user(user_name: str, password: str):
#     if not await is_password_correct(user_name, password):
#         raise HTTPException(status_code=401, detail="Incorrect password")

#     user_deleted = await del_user(user_name)
#     if user_deleted:
#         return {"message": "User {user_name} deleted successfully"}
#     else:
#         raise HTTPException(status_code=404, detail="User not found")




# @app.put("/update_user/{user_name}")
# async def update_user(
#     user_name: str,
#     user_fullName: str = "",
#     user_email: str = "",
#     user_add: str = "",
# ):
#     user_updated = await up_user(user_name, user_fullName, user_email, user_add)

#     if user_updated:
#         return {"message": "User {user_name} updated successfully"}
#     else:
#         raise HTTPException(status_code=404, detail="User not found")




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

@app.post("/login_user")
async def login_user(user_name: str, user_pass: str):
    user = await collection.find_one({"user_name": user_name})
    if not user:
        raise HTTPException(status_code=401, detail="User Not Found")

    if not bcrypt.checkpw(user_pass.encode('utf-8'), user['user_pass'].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Password notn match")

    # Access token
    access_token_data = {"data": user_name}
    access_token = generate_access_token(access_token_data)

    # Refresh token
    refresh_token_data = {"data": user_name}
    refresh_token = generate_refresh_token(refresh_token_data)

    await collection.update_one(
                                    {"user_name": user_name}, 
                                    {"$set": {"access_token": access_token, "refresh_token": refresh_token}}
                                )

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer", "message": "Login successful"}




async def ref_token(user_name: str):
    user = await collection.find_one({"user_name": user_name})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    refresh_token = user.get('refresh_token')
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token not theere")

    decoded_refresh_token = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
    if user.get('refresh_token') != refresh_token:
        raise HTTPException(status_code=401, detail="Wrong refresh token")

    access_token_data = {"data": user_name}
    new_access_token = generate_access_token(access_token_data)
    await collection.update_one(
                                    {"user_name": user_name}, 
                                    {"$set": {"access_token": new_access_token}}
                                )

    return new_access_token

@app.post("/refresh-token")
async def refresh_access_token(user_name: str):
    new_access_token = await ref_token(user_name)
    return {"new_access_token": new_access_token}




async def get_current_user_role(token: str):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    # logging.info("payload: %s",json.dumps(payload, indent=2))

    username: str = str(payload.get("data"))
    # logging.info("username: %s",username)

    user = await collection.find_one({"user_name": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    role = user.get('role')
    
    if username is None:
        raise HTTPException(status_code=400, detail="User role not defined")
    return role

def has_permission(current_user_role, new_user_role):
    role_hierarchy = {"principal": 0, "head": 1, "teacher": 2, "student": 3}

    return role_hierarchy[current_user_role] < role_hierarchy[new_user_role]


@app.post("/create_user")
async def create_user(user: User, current_user_name: str , current_user_pass : str):
    current_user = await collection.find_one({"user_name": current_user_name})
    if not current_user:
        raise HTTPException(status_code=401, detail="User Not Found")

    access_token = current_user.get('access_token')
    current_user_role = await get_current_user_role(access_token)

    if not bcrypt.checkpw(current_user_pass.encode('utf-8'), current_user['user_pass'].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Password notn match")

    if not has_permission(current_user_role, user.role):
        raise HTTPException(status_code=403, detail="Insufficient permissions to create")

    if await collection.count_documents({
        "$or": [{"user_name": user.user_name}, {"user_email": user.user_email}]
    }) > 0:
        raise HTTPException(status_code=400, detail="User already exists.")

    if not is_valid_email(user.user_email):
        raise HTTPException(status_code=422, detail="Email not valid")

    if not 8 <= len(user.user_pass) <= 16:
        raise HTTPException(status_code=422, detail="Password too short or too long")

    hashed_password = bcrypt.hashpw(user.user_pass.encode('utf-8'), bcrypt.gensalt())

    new_user_details = {
        "user_name": user.user_name,
        "user_fullName": user.user_fullName,
        "user_email": user.user_email,
        "user_add": user.user_add,
        "user_pass": hashed_password.decode('utf-8'),
        "role": user.role or "student"
    }

    await collection.insert_one(new_user_details)

    return {"message": "User created successfully"}




async def up_user(user_name: str, user_fullName: str, user_email: str, user_add: str):
    update_data = {}
    if user_fullName:
        update_data['user_fullName'] = user_fullName
    if user_email and is_valid_email(user_email):
        update_data['user_email'] = user_email
    if user_add:
        update_data['user_add'] = user_add

    result = await collection.update_one({"user_name": user_name}, {"$set": update_data})
    return result.modified_count > 0

@app.put("/update_user/{user_name}")
async def update_user(
    current_user_name: str,
    current_user_pass : str,
    user_name: str,
    user_fullName: str = "",
    user_email: str = "",
    user_add: str = "",
):
    current_user = await collection.find_one({"user_name": current_user_name})
    if not current_user:
        raise HTTPException(status_code=401, detail="User Not Found")
    
    access_token = current_user.get('access_token')
    current_user_role = await get_current_user_role(access_token)

    user = await collection.find_one({"user_name": user_name})
    if not user:
        raise HTTPException(status_code=401, detail="User Not Found")
    
    user_role = user.get('role')

    if not bcrypt.checkpw(current_user_pass.encode('utf-8'), current_user['user_pass'].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Password notn match")
     
    if not has_permission(current_user_role, user_role):
        raise HTTPException(status_code=403, detail="Insufficient permissions to update")

    user_updated = await up_user(user_name, user_fullName, user_email, user_add)

    if user_updated:
        return {"message": f"User {user_name} updated successfully by {current_user_role}"}
    else:
        raise HTTPException(status_code=404, detail="User not found")
    



async def del_user(user_name: str):
    result = await collection.delete_one({"user_name": user_name})
    return result.deleted_count > 0

async def is_password_correct(user_name: str, password: str):
    user = await collection.find_one({"user_name": user_name})
    if user and bcrypt.checkpw(password.encode('utf-8'), user["user_pass"].encode('utf-8')):
        return True
    return False

@app.delete("/delete_user/{user_name}")
async def delete_user(
    user_name: str,
    current_user_password: str,
    current_user_name: str
):
    current_user = await collection.find_one({"user_name": current_user_name})
    if not current_user:
        raise HTTPException(status_code=401, detail="User Not Found")

    access_token = current_user.get('access_token')
    current_user_role = await get_current_user_role(access_token)

    user = await collection.find_one({"user_name": user_name})
    if not user:
        raise HTTPException(status_code=401, detail="User Not Found")
    
    user_role = user.get('role')

    if not has_permission(current_user_role, user_role):
        raise HTTPException(status_code=403, detail="Insufficient permissions to delete")

    if not await is_password_correct(current_user_name, current_user_password):
        raise HTTPException(status_code=401, detail="Incorrect password")

    user_deleted = await del_user(user_name)

    if user_deleted:
        return {"message": f"User {user_name} deleted successfully by {current_user_role}"}
    else:
        raise HTTPException(status_code=404, detail="User not found")




async def get_user(user_name: str):
    user = await collection.find_one({"user_name": user_name})
    if not user:
        return None
    user["_id"] = str(user["_id"])
    return user
    
@app.get("/view_users")
async def view_users(userToFind:str,current_user_name: str , current_user_pass:str):
    current_user = await collection.find_one({"user_name": current_user_name})
    if not current_user:
        raise HTTPException(status_code=401, detail="User Not Found")

    access_token = current_user.get('access_token')
    current_user_role = await get_current_user_role(access_token)

    user = await collection.find_one({"user_name": userToFind})
    if not user:
        raise HTTPException(status_code=401, detail="User Not Found")
    
    user_role = user.get('role')

    if not bcrypt.checkpw(current_user_pass.encode('utf-8'), current_user['user_pass'].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Password notn match")

    if not has_permission(current_user_role, user_role):
        raise HTTPException(status_code=403, detail="Insufficient permissions to View")
    users = await get_user(userToFind)
    return users



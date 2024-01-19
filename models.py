from pydantic import BaseModel

class User(BaseModel):
    user_name: str
    user_fullName: str
    user_email: str
    user_add: str
    user_pass: str
    role:str
    access_token: str = ""
    refresh_token: str = ""

# class UserCreatePrincipal(User):
#     role = "principal"

# class UserCreateHead(User):
#     role = "head"

# class UserCreateTeacher(User):
#     role = "teacher"

# class UserCreateStudent(User):
#     role = "student"

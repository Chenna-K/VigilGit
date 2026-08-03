from fastapi import APIRouter, Depends
from database.schema.user import UserInCreate, UserInLogin, UserWithToken, UserOutput
from database.database import get_db
from sqlalchemy.orm import Session
from service.userService import UserService
authRouter = APIRouter()

@authRouter.post("/login", status_code=200, response_model=UserWithToken)
def login(login_details : UserInLogin, session : Session = Depends(get_db)):
    try:
        return UserService(session=session).login(login_details=login_details)
    except Exception as error:
        print(error)
        raise error

@authRouter.post("/signup", status_code=201, response_model=UserOutput)
def signUp(signup_details : UserInCreate, session : Session = Depends(get_db)):
    try:
        return UserService(session=session).signup(user_data=signup_details)
    except Exception as error:
        print(error)
        raise error
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from database.schema.user import UserInCreate, UserInLogin, UserWithToken, UserOutput, UserUpdate
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from security.limiter import limiter
from database.database import get_db
from sqlalchemy.orm import Session
from service.userService import UserService
from database.utility.protectRoute import get_current_user
authRouter = APIRouter()

@authRouter.post("/login", status_code=200, response_model=UserWithToken)
@limiter.limit("5/1minute")
def login(request: Request, login_details : UserInLogin, session : Session = Depends(get_db)):
    try:
        return UserService(session=session).login(login_details=login_details)
    except Exception as error:
        raise error

@authRouter.delete("/delete", status_code=204)
@limiter.limit("2/1minute")
def delete(request: Request, curr_user = Depends(get_current_user), session : Session = Depends(get_db)):
    try:
        return UserService(session=session).delete(user_id=curr_user.id)
    except Exception as error:
        raise error

@authRouter.patch("/update", status_code=200)
@limiter.limit("2/1minute")
def update(request : Request, update_details : UserUpdate, session : Session = Depends(get_db), curr_user = Depends(get_current_user)):
    try:
        return UserService(session=session).update_user(update_details, curr_user)
    except Exception as error:
        raise error
@authRouter.get("/me", status_code=200, response_model=UserOutput)
@limiter.limit("5/1minute")
def get_my_profile(request : Request, curr_user : UserOutput = Depends(get_current_user), session : Session = Depends(get_db)):
    return curr_user
@authRouter.post("/signup", status_code=201, response_model=UserOutput)
@limiter.limit("5/1minute")
def signUp(request: Request,signup_details : UserInCreate, session : Session = Depends(get_db)):
    try:
        return UserService(session=session).signup(user_data=signup_details)
    except Exception as error:
        raise error
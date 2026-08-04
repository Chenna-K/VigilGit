from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from database.schema.user import UserInCreate, UserInLogin, UserWithToken, UserOutput
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from security.limiter import limiter
from database.database import get_db
from sqlalchemy.orm import Session
from service.userService import UserService
authRouter = APIRouter()

@authRouter.post("/login", status_code=200, response_model=UserWithToken)
@limiter.limit("5/1minute")
def login(request: Request, login_details : UserInLogin, session : Session = Depends(get_db)):
    try:
        return UserService(session=session).login(login_details=login_details)
    except Exception as error:
        print(error)
        raise error

@authRouter.post("/signup", status_code=201, response_model=UserOutput)
@limiter.limit("5/1minute")
def signUp(request: Request,signup_details : UserInCreate, session : Session = Depends(get_db)):
    try:
        return UserService(session=session).signup(user_data=signup_details)
    except Exception as error:
        print(error)
        raise error
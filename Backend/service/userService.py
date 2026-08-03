from database.repository.userRepo import UserRepository
from database.schema.user import UserInCreate, UserInLogin, UserWithToken, UserOutput
from security.hashHelper import HashHelper
from security.authHandler import AuthHandler
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

class UserService:

    def __init__(self, session : Session) -> None:
      self.__userRepository =  UserRepository(session=session)
    def signup(self, user_data : UserInCreate) -> UserOutput:
        if self.__userRepository.user_exist_by_email(email=user_data.email):
            raise HTTPException(status_code=400, detail="User with this email already exists")
        hashed_password = HashHelper.get_password_hash(user_data.password)
        user_data.password = hashed_password
        return self.__userRepository.create_user(user_data=user_data)
    def login(self, login_details : UserInLogin) -> UserWithToken:
        if not self.__userRepository.user_exist_by_email(email=login_details.email):
            raise HTTPException(status_code=400, detail="Please create an account first")
        user = self.__userRepository.get_user_by_email(email=login_details.email)
        if HashHelper.verify_password(login_details.password, user.password):
            token = AuthHandler.sign_jwt(user_id = user.id)
            if token:
                return UserWithToken(token=token)
            raise HTTPException(status_code=400, detail="Unable to generate token")
        raise HTTPException(status_code=400, detail="Invalid credentials")
    def get_user_by_id(self, user_id : int) -> UserOutput:
        if not self.__userRepository.user_exists_by_id(id=user_id):
            raise HTTPException(status_code=400, detail="User not found")
        user = self.__userRepository.get_user_by_id(id=user_id)
        return user
    



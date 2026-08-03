from .base import BaseRepository
from ..models.user import User
from ..schema.user import UserInCreate

class UserRepository(BaseRepository):
    def create_user(self, user_data: UserInCreate):
        newUser = User(**user_data.model_dump(exclude_none=True))
        self.session.add(instance=newUser)
        self.session.commit()
        self.session.refresh(instance=newUser)
        return newUser
    def user_exist_by_email(self, email : str) -> bool:
        user = self.session.query(User).filter_by(email=email).first()
        return bool(user)
    def user_exists_by_id(self, id : int) -> bool:
        user = self.session.query(User).filter_by(id=id).first()
        return bool(user)
    def get_user_by_email(self, email : str) -> User:
        user = self.session.query(User).filter_by(email=email).first()
        return user
    def get_user_by_id(self, id : int) -> User:
        user = self.session.query(User).filter_by(id=id).first()
        return user
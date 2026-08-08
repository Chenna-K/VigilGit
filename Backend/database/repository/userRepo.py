from .base import BaseRepository
from ..models.user import User
from ..schema.user import UserInCreate, UserDelete, UserDelete, UserUpdate
from multipledispatch import dispatch

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
    def is_user_admin(self, id : int) -> bool:
        exists = user_exists_by_id(id=id)
        if exists:
            user = get_user_by_id(id=id)
            return user.is_admin
        return False
    
    def get_all_users(self, skip: int = 0, limit: int = 100) -> list[User]:
        return self.session.query(User).offset(skip).limit(limit).all()
    def update_user(self, user_data: UserUpdate) -> bool:
        exists = self.user_exists_by_id(id=UserUpdate.id)
        if exists:
            user = self.get_user_by_id(id=UserUpdate.id)
            update_dict = user_data.model_dump(exclude_unset=True)
            for key, value in update_dict.items():
                setattr(user, key, value)
            self.session.commit()
            self.session.refresh(user)
            return True
        return False

    def delete_user(self, id: int):
        exists = self.user_exists_by_id(id=id)
        if exists:
            user = self.get_user_by_id(id=id)
            self.session.delete(instance=user)
            self.session.commit()
            return True
        return False

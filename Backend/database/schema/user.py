from pydantic import EmailStr, BaseModel
from typing import Union


class UserInCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str

class UserOutput(BaseModel):
    id: int
    first_name: str
    last_name: str
    email: EmailStr
    is_admin : bool

class UserUpdate(BaseModel):
    id: int 
    first_name: Union[str, None ]  = None
    last_name: Union[str, None ] = None
    email: Union[EmailStr, None ] = None
    password: Union[str, None] = None

class AdminUserUpdate(BaseModel):
    is_admin: bool

class UserInLogin(BaseModel):
    email: EmailStr
    password: str

class UserWithToken(BaseModel):
    token : str

class UserDelete(BaseModel):
    id : int

class ScanCreate(BaseModel):
    target_folder: str

class ScanResponse(BaseModel):
    status: str
    total_leaks_found: int
    results: list[dict]

class EmailReport(BaseModel):
    recipient_email: EmailStr
    token_leaks_found: int
    results: list[dict]
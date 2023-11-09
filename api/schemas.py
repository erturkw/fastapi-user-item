from typing import List, Optional
from pydantic import BaseModel


class ItemBase(BaseModel):
    title: str
    description: Optional[str] = None


class ItemCreate(ItemBase):
    pass


class Item(ItemBase):
    id: int
    owner_id: int

    class Config:
        from_attributes = True


class UserBase(BaseModel):
    email: str
    first_name: str
    last_name: str
    age: int


class UserCreate(UserBase):
    password: str


class PasswordUpdate(BaseModel):
    old_password: str
    new_password: str


class UserDeactivate(BaseModel):
    is_active: bool


class UserUpdate(UserBase):
    role: str
    salary: Optional[float] = None


class User(UserBase):
    id: int
    role: Optional[str] = None
    is_active: bool
    items: List[Item] = []

    class Config:
        from_attributes = True


class UserWithSalary(User):
    salary: Optional[float] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str

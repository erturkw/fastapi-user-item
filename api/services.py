from sqlalchemy.orm import Session
import models, schemas
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from typing import Optional
from database import SessionLocal
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

SECRET_KEY = "notreallysecret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def save_user(db: Session, user: models.User):
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_current_user(token: str = Depends(oauth2_scheme)) -> schemas.TokenData:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
            )
        return schemas.TokenData(email=email)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
        )
    except (jwt.JWTError, Exception):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
        )


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_email(db=db, email=username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    return (
        db.query(models.User).order_by(models.User.id).offset(skip).limit(limit).all()
    )


def create_user_me(db: Session, user: schemas.UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
        age=user.age,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(
        email=user.email,
        hashed_password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
        role=user.role,
        age=user.age,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user(db: Session, user: models.User, user_update: schemas.UserUpdate):
    user.email = user_update.email
    user.first_name = user_update.first_name
    user.last_name = user_update.last_name
    user.role = user_update.role
    user.age = user_update.age
    user.salary = user_update.salary
    db.commit()
    db.refresh(user)
    return user


def update_user_me(db: Session, user: models.User, user_update: schemas.UserBase):
    user.email = user_update.email
    user.first_name = user_update.first_name
    user.last_name = user_update.last_name
    user.age = user_update.age
    db.commit()
    db.refresh(user)
    return user


def delete_user(db: Session, user: models.User):
    db.delete(user)
    db.commit()
    return user


def deactivate_user(
    db: Session, user: models.User, user_deactivate: schemas.UserDeactivate
):
    user.is_active = user_deactivate.is_active
    db.commit()
    db.refresh(user)
    return user


def create_item(db: Session, item: schemas.ItemCreate, user_id: int):
    db_item = models.Item(**item.dict(), owner_id=user_id)
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item


def get_items(db: Session, skip: int = 0, limit: int = 100):
    return (
        db.query(models.Item).order_by(models.Item.id).offset(skip).limit(limit).all()
    )


def get_user_items(db: Session, user_id: int, skip: int = 0, limit: int = 100):
    return (
        db.query(models.Item)
        .filter(models.Item.owner_id == user_id)
        .order_by(models.Item.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_items_by_user(db: Session, owner_id: int):
    items = db.query(models.Item).filter(models.Item.owner_id == owner_id).all()
    return items


def get_item(db: Session, item_id: int):
    return db.query(models.Item).filter(models.Item.id == item_id).first()


def update_item(db: Session, item: models.Item, item_update: schemas.ItemCreate):
    item.title = item_update.title
    item.description = item_update.description
    db.commit()
    db.refresh(item)
    return item


def delete_item(db: Session, item: models.Item):
    db.delete(item)
    db.commit()
    return item


def get_user_with_salary(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

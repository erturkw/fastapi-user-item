from typing import List
from fastapi import Depends, FastAPI, HTTPException,status
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
import services, models, schemas
from database import engine
from datetime import timedelta
from fastapi.security import OAuth2PasswordRequestForm
from services import create_access_token,get_db,oauth2_scheme



models.Base.metadata.create_all(bind=engine)

app = FastAPI()

origins = ["*"] 
 
app.add_middleware( 
    CORSMiddleware, 
    allow_origins=origins, 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"], 
) 
 
 
@app.get("/") 
async def main(): 
    return {"message": "Hello World"}

@app.get("/secure-route/")
async def secure_route(current_user: schemas.TokenData = Depends(oauth2_scheme)):
    return {"message": "This route is protected!"}

@app.post("/token/", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),db: Session = Depends(get_db)):
    user = services.authenticate_user(db,form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=services.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}



@app.post("/users/me", response_model=schemas.User, tags=["Non-Auth"])
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = services.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    return services.create_user_me(db=db, user=user)

@app.get("/users/", response_model=List[schemas.User], tags=["Non-Auth"])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = services.get_users(db, skip=skip, limit=limit)
    return users





@app.get("/users/me", response_model=schemas.User, tags=["User"])
async def get_user_me(current_user: schemas.TokenData = Depends(services.get_current_user), db: Session = Depends(get_db)):
    db_user = services.get_user_by_email(db, email=current_user.email)
    return db_user

@app.put("/users/me", response_model=schemas.User, tags=["User"])
async def update_user(user_update: schemas.UserBase,current_user: schemas.TokenData = Depends(services.get_current_user), db: Session = Depends(get_db)):
    db_user = services.get_user_by_email(db,email=current_user.email)
    if db_user is None:
            raise HTTPException(status_code=404, detail="User cant find please relogin")         
    if not db_user.is_active:
        raise HTTPException(status_code=400, detail="User is not active and cannot be updated")
    if user_update.email != db_user.email:
        new_email_user = services.get_user_by_email(db, email=user_update.email)
        if new_email_user:
            raise HTTPException(status_code=400, detail="Email already registered") 
        else:
          updated_user=services.update_user_me(db=db, user=db_user,user_update=user_update)
          new_token = create_access_token(data={"sub": updated_user.email}, expires_delta=timedelta(minutes=0))
          raise HTTPException(status_code=401, detail="The user has been successfully updated, you must log in again because the email address has been changed.")
    return services.update_user_me(db=db, user=db_user,user_update=user_update)

@app.patch("/users/me/change-password", response_model=schemas.User, tags=["User"])
async def change_password(
    password_update: schemas.PasswordUpdate,
    current_user: schemas.TokenData = Depends(services.get_current_user),
    db: Session = Depends(get_db)
):
    db_user = services.get_user_by_email(db, email=current_user.email)
    
    if not db_user.is_active:
        raise HTTPException(status_code=400, detail="User is not active and cannot change the password")
    
    if not services.verify_password(password_update.old_password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Old password is incorrect")
    
    db_user.hashed_password = services.get_password_hash(password_update.new_password)
    db.commit()
    
    return db_user

@app.patch("/users/me", response_model=schemas.UserDeactivate, tags=["User"])
def deactivate_user(user_deactivate: schemas.UserDeactivate,current_user: schemas.TokenData = Depends(services.get_current_user), db: Session = Depends(get_db)):
    db_user = services.get_user_by_email(db, email=current_user.email)
    return services.deactivate_user(db=db, user=db_user, user_deactivate=user_deactivate)



@app.post("/items/me", response_model=schemas.Item, tags=["Item"])
def create_item(item: schemas.ItemCreate, current_user: schemas.TokenData = Depends(services.get_current_user), db: Session = Depends(get_db)):
    db_user = services.get_user_by_email(db, email=current_user.email)
    if not db_user.is_active:
        raise HTTPException(status_code=400, detail="User is not active and Their item cannot be updated")
    return services.create_item(db=db, item=item, user_id=db_user.id)

@app.get("/items/me", response_model=List[schemas.Item], tags=["Item"])
def read_my_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(services.get_current_user)):
    db_user = services.get_user_by_email(db, email=current_user.email)
    if db_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
   
    items = services.get_user_items(db, user_id=db_user.id, skip=skip, limit=limit)
    return items

@app.put("/items/me{item_id}", response_model=schemas.Item, tags=["Item"])
def update_item(item_id: int, item_update: schemas.ItemCreate, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(services.get_current_user)):
    db_user = services.get_user_by_email(db, email=current_user.email)
    db_item = services.get_item(db, item_id=item_id)
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    if db_item.owner_id != db_user.id:
        raise HTTPException(status_code=404, detail="Please write a Item that registired with you.")
    return services.update_item(db=db, item=db_item, item_update=item_update)

@app.delete("/items/me{item_id}", response_model=schemas.Item, tags=["Item"])
def delete_item(item_id: int, db: Session = Depends(get_db), current_user: schemas.TokenData = Depends(services.get_current_user)):
    db_user = services.get_user_by_email(db, email=current_user.email)
    db_item = services.get_item(db, item_id=item_id)
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    if db_item.owner_id != db_user.id:
        raise HTTPException(status_code=404, detail="Please write a Item that registired with you.")
    return services.delete_item(db=db, item=db_item)



@app.get("/users/w", response_model=List[schemas.UserWithSalary], tags=["Admin-User"])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    db_user = services.get_user_by_email(db, email=current_user.email)
    if db_user.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    
    users = services.get_users(db, skip=skip, limit=limit)
    return users

@app.get("/users/{user_id}", response_model=schemas.UserWithSalary, tags=["Admin-User"])
def read_user(user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    db_user = services.get_user(db, user_id=user_id)
   
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@app.put("/users/{user_id}", response_model=schemas.UserWithSalary, tags=["Admin-User"])
def update_user(user_id: int, user_update: schemas.UserUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    db_user = services.get_user(db, user_id=user_id)
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not db_user.is_active:
        raise HTTPException(status_code=400, detail="User is not active and cannot be updated")
    if user_update.email != db_user.email:
        new_email_user = services.get_user_by_email(db, email=user_update.email)
        if new_email_user:
            raise HTTPException(status_code=400, detail="Email already registered")
    return services.update_user(db=db, user=db_user, user_update=user_update)

@app.patch("/users/reset-password/{user_id}", response_model=schemas.User, tags=["Admin-User"])
def reset_password(user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    db_user = services.get_user(db, user_id=user_id)
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    default_password = "12345"

    default_password_hash = services.get_password_hash(default_password)

    db_user.hashed_password = default_password_hash
    services.save_user(db, db_user)

    return db_user

@app.patch("/users/{user_id}", response_model=schemas.UserDeactivate, tags=["Admin-User"])
def deactivate_user(user_id: int, user_deactivate: schemas.UserDeactivate, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    db_user = services.get_user(db, user_id=user_id)
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return services.deactivate_user(db=db, user=db_user, user_deactivate=user_deactivate)

@app.delete("/users/{user_id}", response_model=schemas.User, tags=["Admin-User"])
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    db_user = services.get_user(db, user_id=user_id)
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if db_user.role == "admin":
        raise HTTPException (status_code=403, detail="Can't delete a admin")
    items = services.get_items_by_user(db, owner_id=user_id)
    if items:
        raise HTTPException(status_code=500, detail="User has associated items. Delete the items first.")
    return services.delete_user(db=db, user=db_user)



@app.post("/items/", response_model=schemas.Item, tags=["Admin-Item"])
def create_item(item: schemas.ItemCreate, user_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    db_user = services.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not db_user.is_active:
        raise HTTPException(status_code=400, detail="User is not active and Their item cannot be updated")
    return services.create_item(db=db, item=item, user_id=user_id)

@app.get("/items/", response_model=List[schemas.Item], tags=["Admin-Item"])
def read_items(skip: int = 0, limit: int = 100, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    items = services.get_items(db, skip=skip, limit=limit)
    return items

@app.put("/items/{item_id}", response_model=schemas.Item, tags=["Admin-Item"])
def update_item(item_id: int, item_update: schemas.ItemCreate, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    db_item = services.get_item(db, item_id=item_id)
    if db_item is None:
        
        raise HTTPException(status_code=404, detail="Item not found")
 
    return services.update_item(db=db, item=db_item, item_update=item_update)

@app.delete("/items/{item_id}", response_model=schemas.Item, tags=["Admin-Item"])
def delete_item(item_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(services.get_current_user)):
    crtuser = services.get_user_by_email(db, email=current_user.email)
    if crtuser.role != "admin":
        raise HTTPException(status_code=403, detail="You are not authorized for this operation.")
    db_item = services.get_item(db, item_id=item_id)
    if db_item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return services.delete_item(db=db, item=db_item)








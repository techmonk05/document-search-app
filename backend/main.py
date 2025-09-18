from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import crud, models, schemas, security
from database import SessionLocal, engine
import secrets
import string

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def generate_temporary_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))



@app.post("/api/signup", response_model=schemas.UserResponse)
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    temp_password = generate_temporary_password()
    

    print("----------------------------------------------------")
    print(f"SIGNUP: New user '{user.email}'")
    print(f"TEMPORARY PASSWORD: {temp_password}")
    print("----------------------------------------------------")

    hashed_password = security.get_password_hash(temp_password)
    created_user = crud.create_user(db=db, email=user.email, hashed_password=hashed_password)
    
    return {"id": created_user.id, "email": created_user.email}


@app.post("/api/login")
def login(form_data: schemas.UserLogin, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, email=form_data.email)
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = security.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/api/forgot-password")
def forgot_password(request: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, email=request.email)
    if user:
        reset_token = security.create_reset_token()
        crud.store_reset_token(db, user=user, token=reset_token)

        reset_link = f"http://localhost:5173/reset-password?token={reset_token}"
        
  
        print("----------------------------------------------------")
        print(f"FORGOT PASSWORD: User '{request.email}'")
        print(f"RESET LINK: {reset_link}")
        print("----------------------------------------------------")

    return {"message": "If an account with that email exists, a password reset link has been sent."}


@app.post("/api/reset-password")
def reset_password(request: schemas.ResetPasswordRequest, db: Session = Depends(get_db)):
    user = crud.get_user_by_reset_token(db, token=request.token)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    hashed_password = security.get_password_hash(request.new_password)
    crud.update_user_password(db, user=user, hashed_password=hashed_password)
    
    return {"message": "Your password has been successfully reset."}


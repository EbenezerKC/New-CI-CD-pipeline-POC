import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException
from jose import jwt
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.database import Base, engine, get_db
from app.models import User
from app.schemas import UserCreate, UserResponse, Token


app = FastAPI(
    title="Glynac Auth Service",
    version="1.0.0"
)

Base.metadata.create_all(bind=engine)

password_hasher = PasswordHasher()

SECRET_KEY = os.getenv("JWT_SECRET", "glynac-dev-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


@app.get("/")
def root():
    return {
        "service": "glynac-auth",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post(
    "/auth/register",
    response_model=UserResponse
)
def register(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    existing_user = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    password_hash = password_hasher.hash(user.password)

    new_user = User(
        email=user.email,
        password_hash=password_hash
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@app.post(
    "/auth/login",
    response_model=Token
)
def login(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    existing_user = (
        db.query(User)
        .filter(User.email == user.email)
        .first()
    )

    if not existing_user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    try:
        password_hasher.verify(
            existing_user.password_hash,
            user.password
        )
    except VerifyMismatchError:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    token_data = {
        "sub": existing_user.email,
        "exp": expire
    }

    access_token = jwt.encode(
        token_data,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return {
        "access_token": access_token,
        "token_type": "bearer"
    } 

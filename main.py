from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Load the required access token from environment variables
REQUIRED_ACCESS_TOKEN = os.getenv("ALLOWED_ACCESS_TOKEN")
if REQUIRED_ACCESS_TOKEN is None:
    raise ValueError("REQUIRED_ACCESS_TOKEN environment variable is not set")

# Dummy database
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "full_name": "Test User",
        "email": "test@example.com",
        "hashed_password": "$2b$12$GMWcQ3/fQ0hQA48R4gsSdOySTraFW3qK1AQhI2jEw79mli8phDv8a",  # Password is 'password'
        
    },
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$T3LdXSIubF/bHk2PZ4iCRu7pCNBzFQ3DelZJZISfXa.NM83pSk4iy", #password1
        
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "$2b$12$wvZLUEi465aRDgL.4yKD0OD8DCkX6JgRbz2y.ksqUtx0SHlG1za5O",#password2
        
    },
}

# Function to verify password
def verify_password(plain_password, hashed_password):
    #return True
    print("Hashed password is ",plain_password)
    return pwd_context.verify(plain_password, hashed_password)

# Function to authenticate user
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

# OAuth2PasswordBearer for authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Route for login
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = jwt.encode({"username": user["username"]}, "SECRET_KEY", algorithm="HS256")
    return {"access_token": access_token, "token_type": "bearer"}

# Route for protected feature
@app.get("/protected")
async def protected_route(authorization: str = Depends(oauth2_scheme)):
    print(authorization)
    try:
        token = authorization
        decoded_token = jwt.decode(token, "SECRET_KEY", algorithms=["HS256"])
        print(decoded_token["username"]," vvv ",REQUIRED_ACCESS_TOKEN)
        if decoded_token["username"] != REQUIRED_ACCESS_TOKEN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid access token",
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid access token",
        )
    return {"message": "This is a protected feature"}

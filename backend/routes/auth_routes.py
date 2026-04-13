from fastapi import APIRouter, HTTPException, Request, Response, Depends
from models.user import UserCreate, UserLogin, UserResponse
from services.auth_service import register_user, login_user
from utils.auth_utils import create_access_token, create_refresh_token, get_current_user
from bson import ObjectId
import jwt
import os

JWT_ALGORITHM = "HS256"

def create_auth_router(db):
    router = APIRouter(prefix="/auth", tags=["auth"])

    @router.post("/register")
    async def register(user_data: UserCreate, request: Request, response: Response):
        user = await register_user(db, user_data.email, user_data.password, user_data.name or "User")
        access_token = create_access_token(user["_id"], user["email"])
        refresh_token = create_refresh_token(user["_id"])
        
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=900,
            path="/"
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=604800,
            path="/"
        )
        return user

    @router.post("/login")
    async def login(credentials: UserLogin, request: Request, response: Response):
        ip = request.client.host
        user = await login_user(db, credentials.email, credentials.password, ip)
        access_token = create_access_token(user["_id"], user["email"])
        refresh_token = create_refresh_token(user["_id"])
        
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=900,
            path="/"
        )
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=False,
            samesite="lax",
            max_age=604800,
            path="/"
        )
        return user

    @router.post("/logout")
    async def logout(request: Request, response: Response):
        response.delete_cookie(key="access_token", path="/")
        response.delete_cookie(key="refresh_token", path="/")
        return {"message": "Logged out successfully"}

    @router.get("/me")
    async def get_me(request: Request):
        user = await get_current_user(request, db)
        return user

    @router.post("/refresh")
    async def refresh(request: Request, response: Response):
        token = request.cookies.get("refresh_token")
        if not token:
            raise HTTPException(status_code=401, detail="Refresh token not found")
        try:
            payload = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=[JWT_ALGORITHM])
            if payload.get("type") != "refresh":
                raise HTTPException(status_code=401, detail="Invalid token type")
            
            user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            
            access_token = create_access_token(str(user["_id"]), user["email"])
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                secure=False,
                samesite="lax",
                max_age=900,
                path="/"
            )
            return {"message": "Token refreshed"}
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Refresh token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

    return router

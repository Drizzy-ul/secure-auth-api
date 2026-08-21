"""Aggregated API v1 router."""

from fastapi import APIRouter

from app.api.v1.endpoints import admin, auth, mfa, users

api_router = APIRouter()

api_router.include_router(auth.router)
api_router.include_router(mfa.router)
api_router.include_router(users.router)
api_router.include_router(admin.router)

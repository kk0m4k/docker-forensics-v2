#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Docker Forensics API Server with JWT Authentication

This module implements an alternative version of the FastAPI server that uses
JWT (JSON Web Token) authentication instead of simple API keys. It demonstrates
how to implement a more sophisticated authentication flow with login endpoints
and token-based access control.

Features:
    - JWT-based authentication with login endpoint
    - Token generation and verification
    - User context from JWT claims
    - RESTful API endpoints for artifact management
    - Background processing tasks

Classes:
    LoginRequest: Pydantic model for login requests
    LoginResponse: Pydantic model for login responses

Functions:
    login: Generate JWT token with API key
    verify_jwt: Dependency for JWT verification
    get_current_user: Get user info from JWT

Author: Kim, Tae hoon (Francesco)
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime
import uuid
from .models import ArtifactModel, ArtifactResponse, HealthResponse
from .database import Database
from .auth import verify_api_key, generate_token, verify_token
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Docker Forensics API with JWT",
    description="REST API with JWT authentication",
    version="2.0.0"
)

# Initialize database
db = Database()

# Security
security = HTTPBearer()


class LoginRequest(BaseModel):
    """
    Login request model for JWT authentication.
    
    Attributes:
        api_key (str): API key for authentication
    """
    api_key: str


class LoginResponse(BaseModel):
    """
    Login response model containing JWT token.
    
    Attributes:
        access_token (str): JWT access token
        token_type (str): Token type (always "bearer")
        expires_in (int): Token expiration time in seconds
    """
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400  # 24 hours


@app.post("/api/v1/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    Login endpoint to exchange API key for JWT token.
    
    Args:
        request (LoginRequest): Login request containing API key
    
    Returns:
        LoginResponse: JWT token and metadata
    
    Raises:
        HTTPException: If API key is invalid (401)
    """
    
    # Verify API key
    if not verify_api_key(request.api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Generate JWT token
    token = generate_token(user_id="forensics_user", additional_claims={
        "scope": "artifacts:read artifacts:write",
        "client": "docker-forensics"
    })
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 86400
    }


async def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    FastAPI dependency to verify JWT tokens.
    
    Args:
        credentials (HTTPAuthorizationCredentials): Bearer token from Authorization header
    
    Returns:
        dict: Decoded JWT payload containing user claims
    
    Raises:
        HTTPException: If token is invalid or expired (401)
    """
    token = credentials.credentials
    payload = verify_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return payload


@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint (no authentication required).
    
    Returns:
        HealthResponse: Service health status and metadata
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "database": await db.health_check()
    }


@app.post("/api/v1/artifacts", response_model=ArtifactResponse)
async def create_artifact(
    artifact: ArtifactModel,
    background_tasks: BackgroundTasks,
    token_payload: dict = Depends(verify_jwt)
):
    """
    Create a new artifact entry (JWT authentication required).
    
    Args:
        artifact (ArtifactModel): Artifact data to store
        background_tasks (BackgroundTasks): FastAPI background tasks manager
        token_payload (dict): Decoded JWT payload with user info
    
    Returns:
        ArtifactResponse: Created artifact ID and status
    
    Raises:
        HTTPException: If creation fails (500)
    """
    
    try:
        # Generate unique ID
        artifact_id = str(uuid.uuid4())
        
        # Prepare artifact document
        artifact_doc = {
            "id": artifact_id,
            "container_id": artifact.metadata.container_id,
            "collection_timestamp": artifact.metadata.collection_timestamp,
            "collection_host": artifact.metadata.collection_host,
            "artifact_count": artifact.metadata.artifact_count,
            "checksum": artifact.metadata.checksum,
            "created_at": datetime.now().isoformat(),
            "created_by": token_payload.get("user_id", "unknown"),
            "status": "received",
            "artifacts": artifact.artifacts
        }
        
        # Store in database
        await db.store_artifact(artifact_doc)
        
        # Background task for processing
        background_tasks.add_task(process_artifact, artifact_id, artifact_doc)
        
        logger.info(f"Created artifact {artifact_id} by user {token_payload.get('user_id')}")
        
        return {
            "id": artifact_id,
            "message": "Artifact received successfully",
            "status": "received",
            "container_id": artifact.metadata.container_id
        }
        
    except Exception as e:
        logger.error(f"Failed to create artifact: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/api/v1/artifacts/{artifact_id}")
async def get_artifact(
    artifact_id: str,
    token_payload: dict = Depends(verify_jwt)
):
    """
    Get artifact by ID (JWT authentication required).
    
    Args:
        artifact_id (str): Unique artifact identifier
        token_payload (dict): Decoded JWT payload with user info
    
    Returns:
        dict: Complete artifact data
    
    Raises:
        HTTPException: If artifact not found (404)
    """
    
    artifact = await db.get_artifact(artifact_id)
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    return artifact


@app.get("/api/v1/me")
async def get_current_user(token_payload: dict = Depends(verify_jwt)):
    """
    Get current user information from JWT token.
    
    Args:
        token_payload (dict): Decoded JWT payload
    
    Returns:
        dict: User information including ID, scope, and expiration
    """
    return {
        "user_id": token_payload.get("user_id"),
        "scope": token_payload.get("scope"),
        "expires_at": datetime.fromtimestamp(token_payload.get("exp")).isoformat()
    }


async def process_artifact(artifact_id: str, artifact_doc: Dict[str, Any]):
    """
    Background task to process artifact after storage.
    
    This function runs asynchronously after artifact creation to perform
    additional processing such as validation, indexing, and analysis.
    
    Args:
        artifact_id (str): Unique artifact identifier
        artifact_doc (Dict[str, Any]): Complete artifact document
    """
    try:
        await db.update_artifact_status(artifact_id, "processing")
        # Processing logic here
        await db.update_artifact_status(artifact_id, "processed")
        logger.info(f"Processed artifact {artifact_id}")
    except Exception as e:
        logger.error(f"Failed to process artifact {artifact_id}: {str(e)}")
        await db.update_artifact_status(artifact_id, "error", str(e))


@app.on_event("startup")
async def startup_event():
    """
    Initialize application on startup.
    
    Creates database connections and prepares the application
    for serving requests.
    """
    await db.initialize()
    logger.info("Docker Forensics API server (JWT) started")


@app.on_event("shutdown")
async def shutdown_event():
    """
    Cleanup resources on application shutdown.
    
    Closes database connections and performs cleanup tasks
    before the application terminates.
    """
    await db.close()
    logger.info("Docker Forensics API server (JWT) stopped")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
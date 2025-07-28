#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Docker Forensics API Server with JWT Authentication

This module implements the FastAPI-based REST API server for receiving and storing
Docker forensics artifacts with JWT-based authentication.

Features:
    - JWT-based authentication with login endpoint
    - RESTful API endpoints for artifact management
    - Chunked upload support for large artifacts
    - Background processing tasks
    - File-based database storage

Author: Kim, Tae hoon (Francesco)
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
from datetime import datetime
import os
import json
import uuid
import base64
from .models import ArtifactModel, ArtifactResponse, HealthResponse, ChunkedUploadInit, ChunkData
from .database import Database
from .auth import verify_api_key, generate_token, verify_token
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize database
db = Database()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown events."""
    # Startup
    await db.initialize()
    logger.info("Docker Forensics API server started")
    yield
    # Shutdown
    await db.close()
    logger.info("Docker Forensics API server stopped")

# Initialize FastAPI app
app = FastAPI(
    title="Docker Forensics API",
    description="REST API for receiving and storing Docker forensics artifacts with JWT authentication",
    version="2.0.0",
    lifespan=lifespan
)

# Security
security = HTTPBearer()

# Temporary storage for chunked uploads
chunked_uploads = {}


class LoginRequest(BaseModel):
    """Login request model for JWT authentication"""
    api_key: str


class LoginResponse(BaseModel):
    """Login response model containing JWT token"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400  # 24 hours


# === Authentication Dependency ===
async def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    FastAPI dependency to verify JWT tokens.
    
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


# === Authentication Endpoints ===
@app.post("/api/v1/auth/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    Login endpoint to exchange API key for JWT token.
    
    Args:
        request: Login request containing API key
    
    Returns:
        JWT token and metadata
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


@app.get("/api/v1/me")
async def get_current_user(token_payload: dict = Depends(verify_jwt)):
    """Get current user information from JWT token"""
    return {
        "user_id": token_payload.get("user_id"),
        "scope": token_payload.get("scope"),
        "expires_at": datetime.fromtimestamp(token_payload.get("exp")).isoformat()
    }


# === Health Check Endpoint ===
@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint (no authentication required)"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "database": await db.health_check()
    }


# === Artifact Management Endpoints ===
@app.post("/api/v1/artifacts", response_model=ArtifactResponse)
async def create_artifact(
    artifact: ArtifactModel,
    background_tasks: BackgroundTasks,
    token_payload: dict = Depends(verify_jwt)
):
    """Create a new artifact entry"""
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
        
        logger.info(f"Created artifact {artifact_id} for container {artifact.metadata.container_id} by user {token_payload.get('user_id')}")
        
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
    """Get artifact by ID"""
    artifact = await db.get_artifact(artifact_id)
    
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    return artifact


@app.get("/api/v1/artifacts")
async def list_artifacts(
    container_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    token_payload: dict = Depends(verify_jwt)
):
    """List artifacts with optional filtering"""
    artifacts = await db.list_artifacts(
        container_id=container_id,
        limit=limit,
        offset=offset
    )
    
    return {
        "artifacts": artifacts,
        "count": len(artifacts),
        "limit": limit,
        "offset": offset
    }


@app.delete("/api/v1/artifacts/{artifact_id}")
async def delete_artifact(
    artifact_id: str,
    token_payload: dict = Depends(verify_jwt)
):
    """Delete an artifact"""
    success = await db.delete_artifact(artifact_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Artifact not found")
    
    logger.info(f"Deleted artifact {artifact_id} by user {token_payload.get('user_id')}")
    
    return {"message": f"Artifact {artifact_id} deleted successfully"}


# === Chunked Upload Endpoints ===
@app.post("/api/v1/artifacts/chunked/init")
async def init_chunked_upload(
    init_data: ChunkedUploadInit,
    token_payload: dict = Depends(verify_jwt)
):
    """Initialize chunked upload session"""
    session_id = str(uuid.uuid4())
    
    # Store session info
    chunked_uploads[session_id] = {
        "metadata": init_data.metadata,
        "total_chunks": init_data.total_chunks,
        "received_chunks": {},
        "created_at": datetime.now().isoformat(),
        "user_id": token_payload.get("user_id", "unknown")
    }
    
    logger.info(f"Initialized chunked upload session {session_id} by user {token_payload.get('user_id')}")
    
    return {
        "session_id": session_id,
        "message": "Chunked upload session initialized"
    }


@app.post("/api/v1/artifacts/chunked/{session_id}/chunk")
async def upload_chunk(
    session_id: str,
    chunk_data: ChunkData,
    token_payload: dict = Depends(verify_jwt)
):
    """Upload a chunk of data"""
    if session_id not in chunked_uploads:
        raise HTTPException(status_code=404, detail="Upload session not found")
    
    session = chunked_uploads[session_id]
    
    # Verify user owns the session
    if session.get("user_id") != token_payload.get("user_id"):
        raise HTTPException(status_code=403, detail="Not authorized to upload to this session")
    
    # Store chunk
    session["received_chunks"][chunk_data.chunk_number] = chunk_data.chunk_data
    
    logger.info(f"Received chunk {chunk_data.chunk_number} for session {session_id}")
    
    return {
        "message": f"Chunk {chunk_data.chunk_number} received",
        "chunks_received": len(session["received_chunks"]),
        "total_chunks": session["total_chunks"]
    }


@app.post("/api/v1/artifacts/chunked/{session_id}/finalize")
async def finalize_chunked_upload(
    session_id: str,
    background_tasks: BackgroundTasks,
    token_payload: dict = Depends(verify_jwt)
):
    """Finalize chunked upload and reassemble data"""
    if session_id not in chunked_uploads:
        raise HTTPException(status_code=404, detail="Upload session not found")
    
    session = chunked_uploads[session_id]
    
    # Verify user owns the session
    if session.get("user_id") != token_payload.get("user_id"):
        raise HTTPException(status_code=403, detail="Not authorized to finalize this session")
    
    # Verify all chunks received
    if len(session["received_chunks"]) != session["total_chunks"]:
        raise HTTPException(
            status_code=400,
            detail=f"Missing chunks: received {len(session['received_chunks'])}, expected {session['total_chunks']}"
        )
    
    try:
        # Reassemble data
        chunks = []
        for i in range(session["total_chunks"]):
            chunk_data = session["received_chunks"][i]
            chunks.append(base64.b64decode(chunk_data))
        
        reassembled_data = b''.join(chunks).decode('utf-8')
        artifact_data = json.loads(reassembled_data)
        
        # Create artifact
        artifact_id = str(uuid.uuid4())
        
        artifact_doc = {
            "id": artifact_id,
            "container_id": session["metadata"]["container_id"],
            "collection_timestamp": session["metadata"]["collection_timestamp"],
            "collection_host": session["metadata"]["collection_host"],
            "artifact_count": session["metadata"]["artifact_count"],
            "checksum": session["metadata"]["checksum"],
            "created_at": datetime.now().isoformat(),
            "created_by": token_payload.get("user_id", "unknown"),
            "status": "received",
            "artifacts": artifact_data["artifacts"],
            "upload_method": "chunked"
        }
        
        # Store in database
        await db.store_artifact(artifact_doc)
        
        # Clean up session
        del chunked_uploads[session_id]
        
        # Background task for processing
        background_tasks.add_task(process_artifact, artifact_id, artifact_doc)
        
        logger.info(f"Finalized chunked upload for artifact {artifact_id}")
        
        return {
            "id": artifact_id,
            "message": "Chunked upload completed successfully",
            "status": "received"
        }
        
    except Exception as e:
        logger.error(f"Failed to finalize chunked upload: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to process chunked upload: {str(e)}")


# === Background Tasks ===
async def process_artifact(artifact_id: str, artifact_doc: Dict[str, Any]):
    """Background task to process artifact after storage"""
    try:
        # Update status to processing
        await db.update_artifact_status(artifact_id, "processing")
        
        # Here you can add additional processing logic:
        # - Validate artifact integrity
        # - Extract and index specific fields
        # - Generate alerts based on findings
        # - Store to long-term storage
        
        # For now, just mark as processed
        await db.update_artifact_status(artifact_id, "processed")
        
        logger.info(f"Processed artifact {artifact_id}")
        
    except Exception as e:
        logger.error(f"Failed to process artifact {artifact_id}: {str(e)}")
        await db.update_artifact_status(artifact_id, "error", str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
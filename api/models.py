#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API Models Module

This module defines Pydantic models for request/response validation in the
Docker Forensics API. These models ensure type safety and automatic validation
for all API endpoints.

Classes:
    ArtifactMetadata: Metadata model for artifacts
    ArtifactModel: Complete artifact model
    ArtifactResponse: Response model for artifact operations
    HealthResponse: Health check response model
    ChunkedUploadInit: Chunked upload initialization model
    ChunkData: Individual chunk data model
    ArtifactListResponse: Artifact listing response model
    ErrorResponse: Error response model

Author: Kim, Tae hoon (Francesco)
"""

from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from datetime import datetime


class ArtifactMetadata(BaseModel):
    """
    Metadata for forensics artifacts.
    
    Contains essential information about the artifact collection including
    container identification, timestamps, and collection statistics.
    """
    container_id: str = Field(..., description="Docker container ID")
    collection_timestamp: str = Field(..., description="ISO format timestamp of collection")
    collection_host: str = Field(..., description="Hostname where collection occurred")
    collection_user: Optional[str] = Field(None, description="User who performed collection")
    artifact_count: int = Field(..., description="Number of artifacts collected")
    checksum: str = Field(..., description="SHA256 checksum of the artifacts")
    errors: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Collection errors")


class ArtifactModel(BaseModel):
    """Complete artifact model"""
    metadata: ArtifactMetadata
    artifacts: Dict[str, Any] = Field(..., description="Collected artifacts data")


class ArtifactResponse(BaseModel):
    """Response model for artifact creation"""
    id: str = Field(..., description="Unique artifact ID")
    message: str = Field(..., description="Response message")
    status: str = Field(..., description="Artifact status")
    container_id: Optional[str] = Field(None, description="Container ID")


class HealthResponse(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Service health status")
    timestamp: str = Field(..., description="Current timestamp")
    version: str = Field(..., description="API version")
    database: Optional[Dict[str, Any]] = Field(None, description="Database status")


class ChunkedUploadInit(BaseModel):
    """Initialize chunked upload"""
    metadata: Dict[str, Any] = Field(..., description="Artifact metadata")
    total_chunks: int = Field(..., description="Total number of chunks")


class ChunkData(BaseModel):
    """Data for a single chunk"""
    chunk_number: int = Field(..., description="Chunk sequence number")
    chunk_data: str = Field(..., description="Base64 encoded chunk data")
    is_last: bool = Field(False, description="Whether this is the last chunk")


class ArtifactListResponse(BaseModel):
    """Response for artifact listing"""
    artifacts: List[Dict[str, Any]] = Field(..., description="List of artifacts")
    count: int = Field(..., description="Number of artifacts returned")
    limit: int = Field(..., description="Query limit")
    offset: int = Field(..., description="Query offset")


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Detailed error information")
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Database Module

This module provides a simple file-based database implementation for storing
Docker forensics artifacts. It uses JSON files for storage with an index for
quick lookups. In production, this should be replaced with a proper database
like PostgreSQL or MongoDB.

Classes:
    Database: File-based database for artifact storage

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging
import aiofiles
from pathlib import Path


logger = logging.getLogger(__name__)


class Database:
    """
    Simple file-based database for artifacts.
    
    This class provides basic database operations for storing and retrieving
    forensic artifacts using a file-based approach. Each artifact is stored
    as a separate JSON file with an index file for quick lookups.
    
    In production, this should be replaced with a proper database
    like PostgreSQL or MongoDB.
    
    Attributes:
        db_path (Path): Base path for database storage
        artifacts_path (Path): Path for artifact files
        index_path (Path): Path for index file
        lock (asyncio.Lock): Lock for concurrent access control
    """
    
    def __init__(self, db_path: str = "/var/docker-forensics/db"):
        self.db_path = Path(db_path)
        self.artifacts_path = self.db_path / "artifacts"
        self.index_path = self.db_path / "index.json"
        self.lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize database directories"""
        self.artifacts_path.mkdir(parents=True, exist_ok=True)
        
        # Create index if it doesn't exist
        if not self.index_path.exists():
            await self._save_index({})
    
    async def health_check(self) -> Dict[str, Any]:
        """Check database health"""
        try:
            # Check if paths are accessible
            if not self.db_path.exists():
                return {"status": "unhealthy", "error": "Database path does not exist"}
            
            if not os.access(self.db_path, os.W_OK):
                return {"status": "unhealthy", "error": "Database path is not writable"}
            
            # Count artifacts
            artifact_count = len(list(self.artifacts_path.glob("*.json")))
            
            return {
                "status": "healthy",
                "artifact_count": artifact_count,
                "db_path": str(self.db_path)
            }
        except Exception as e:
            return {"status": "unhealthy", "error": str(e)}
    
    async def store_artifact(self, artifact: Dict[str, Any]) -> str:
        """Store artifact in database"""
        artifact_id = artifact["id"]
        
        async with self.lock:
            # Save artifact file
            artifact_file = self.artifacts_path / f"{artifact_id}.json"
            async with aiofiles.open(artifact_file, 'w') as f:
                await f.write(json.dumps(artifact, indent=2))
            
            # Update index
            index = await self._load_index()
            index[artifact_id] = {
                "container_id": artifact.get("container_id"),
                "collection_timestamp": artifact.get("collection_timestamp"),
                "created_at": artifact.get("created_at"),
                "status": artifact.get("status", "stored")
            }
            await self._save_index(index)
        
        logger.info(f"Stored artifact {artifact_id}")
        return artifact_id
    
    async def get_artifact(self, artifact_id: str) -> Optional[Dict[str, Any]]:
        """Get artifact by ID"""
        artifact_file = self.artifacts_path / f"{artifact_id}.json"
        
        if not artifact_file.exists():
            return None
        
        async with aiofiles.open(artifact_file, 'r') as f:
            content = await f.read()
            return json.loads(content)
    
    async def list_artifacts(self, container_id: Optional[str] = None,
                           limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List artifacts with optional filtering"""
        index = await self._load_index()
        
        # Filter by container_id if provided
        if container_id:
            filtered_items = [
                (aid, info) for aid, info in index.items()
                if info.get("container_id") == container_id
            ]
        else:
            filtered_items = list(index.items())
        
        # Sort by creation time (newest first)
        filtered_items.sort(
            key=lambda x: x[1].get("created_at", ""),
            reverse=True
        )
        
        # Apply pagination
        paginated_items = filtered_items[offset:offset + limit]
        
        # Build response
        artifacts = []
        for artifact_id, info in paginated_items:
            artifact_summary = {
                "id": artifact_id,
                "container_id": info.get("container_id"),
                "collection_timestamp": info.get("collection_timestamp"),
                "created_at": info.get("created_at"),
                "status": info.get("status")
            }
            artifacts.append(artifact_summary)
        
        return artifacts
    
    async def update_artifact_status(self, artifact_id: str, status: str,
                                   error: Optional[str] = None):
        """Update artifact status"""
        async with self.lock:
            # Update artifact file
            artifact = await self.get_artifact(artifact_id)
            if artifact:
                artifact["status"] = status
                artifact["updated_at"] = datetime.now().isoformat()
                if error:
                    artifact["error"] = error
                
                artifact_file = self.artifacts_path / f"{artifact_id}.json"
                async with aiofiles.open(artifact_file, 'w') as f:
                    await f.write(json.dumps(artifact, indent=2))
            
            # Update index
            index = await self._load_index()
            if artifact_id in index:
                index[artifact_id]["status"] = status
                await self._save_index(index)
    
    async def delete_artifact(self, artifact_id: str) -> bool:
        """Delete artifact"""
        async with self.lock:
            # Delete artifact file
            artifact_file = self.artifacts_path / f"{artifact_id}.json"
            if artifact_file.exists():
                artifact_file.unlink()
                
                # Update index
                index = await self._load_index()
                if artifact_id in index:
                    del index[artifact_id]
                    await self._save_index(index)
                
                return True
        
        return False
    
    async def _load_index(self) -> Dict[str, Any]:
        """Load index from file"""
        if not self.index_path.exists():
            return {}
        
        async with aiofiles.open(self.index_path, 'r') as f:
            content = await f.read()
            return json.loads(content) if content else {}
    
    async def _save_index(self, index: Dict[str, Any]):
        """Save index to file"""
        async with aiofiles.open(self.index_path, 'w') as f:
            await f.write(json.dumps(index, indent=2))
    
    async def close(self):
        """Close database connections"""
        # For file-based DB, nothing to close
        pass
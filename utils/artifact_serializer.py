#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Artifact Serializer Module

This module handles the serialization, compression, and local storage of collected
forensic artifacts. It provides functionality for JSON serialization with optional
gzip compression and checksum verification.

Classes:
    ArtifactSerializer: Manages artifact serialization and local storage

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import gzip
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
import logging


class ArtifactSerializer:
    """
    Handle serialization and storage of collected artifacts.
    
    This class provides functionality to:
    - Serialize artifacts to JSON format
    - Compress artifacts using gzip
    - Calculate and verify checksums
    - Save artifacts to local storage with organized structure
    - Generate human-readable summary files
    - Load and verify previously saved artifacts
    
    Attributes:
        config (Dict[str, Any]): Configuration dictionary
        logger (logging.Logger): Logger instance
        local_storage_path (str): Base path for local storage
        compression (bool): Whether to use gzip compression
        max_size_mb (int): Maximum storage size limit in MB
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.local_storage_path = config.get('local_storage', {}).get('path', '/var/docker-forensics/artifacts/')
        self.compression = config.get('local_storage', {}).get('compression', True)
        self.max_size_mb = config.get('local_storage', {}).get('max_size_mb', 1000)
    
    def serialize_artifacts(self, container_id: str, artifacts: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize all collected artifacts into a single JSON structure"""
        
        # Create metadata
        metadata = {
            'version': '2.0',
            'container_id': container_id,
            'collection_timestamp': datetime.now().isoformat(),
            'collection_host': os.uname().nodename,
            'collection_user': os.environ.get('USER', 'unknown'),
            'artifact_count': len(artifacts),
            'errors': []
        }
        
        # Collect all errors from collectors
        for collector_name, collector_data in artifacts.items():
            if isinstance(collector_data, dict) and 'errors' in collector_data:
                for error in collector_data['errors']:
                    metadata['errors'].append({
                        'collector': collector_name,
                        'error': error
                    })
        
        # Create final structure
        serialized_data = {
            'metadata': metadata,
            'artifacts': artifacts
        }
        
        # Calculate checksum
        json_str = json.dumps(serialized_data, sort_keys=True, default=str)
        serialized_data['metadata']['checksum'] = hashlib.sha256(json_str.encode()).hexdigest()
        
        return serialized_data
    
    def save_to_local(self, container_id: str, serialized_data: Dict[str, Any]) -> str:
        """Save serialized artifacts to local storage"""
        
        # Create directory structure
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        save_dir = os.path.join(self.local_storage_path, container_id[:12])
        os.makedirs(save_dir, exist_ok=True)
        
        # Generate filename
        filename = f"forensics_{container_id[:12]}_{timestamp}.json"
        if self.compression:
            filename += '.gz'
        
        filepath = os.path.join(save_dir, filename)
        
        try:
            # Check storage limits
            self._check_storage_limits()
            
            # Save file
            if self.compression:
                # Save as compressed JSON
                with gzip.open(filepath, 'wt', encoding='utf-8') as f:
                    json.dump(serialized_data, f, indent=2, default=str)
            else:
                # Save as regular JSON
                with open(filepath, 'w') as f:
                    json.dump(serialized_data, f, indent=2, default=str)
            
            # Log file info
            file_size = os.path.getsize(filepath)
            self.logger.info(f"Saved artifacts to {filepath} (size: {self._format_bytes(file_size)})")
            
            # Save a summary file
            summary_file = os.path.join(save_dir, f"summary_{container_id[:12]}_{timestamp}.txt")
            self._save_summary(summary_file, serialized_data)
            
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to save artifacts: {str(e)}")
            raise
    
    def _check_storage_limits(self):
        """Check if storage limits are exceeded"""
        total_size = 0
        
        try:
            for root, dirs, files in os.walk(self.local_storage_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    total_size += os.path.getsize(filepath)
            
            total_size_mb = total_size / (1024 * 1024)
            
            if total_size_mb > self.max_size_mb:
                self.logger.warning(f"Storage limit exceeded: {total_size_mb:.2f}MB > {self.max_size_mb}MB")
                # Could implement cleanup of old files here
        except Exception as e:
            self.logger.warning(f"Could not check storage limits: {str(e)}")
    
    def _save_summary(self, filepath: str, data: Dict[str, Any]):
        """Save a human-readable summary of the artifacts"""
        try:
            with open(filepath, 'w') as f:
                f.write(f"Docker Forensics Collection Summary\n")
                f.write(f"{'=' * 50}\n\n")
                
                metadata = data.get('metadata', {})
                f.write(f"Container ID: {metadata.get('container_id', 'Unknown')}\n")
                f.write(f"Collection Time: {metadata.get('collection_timestamp', 'Unknown')}\n")
                f.write(f"Collection Host: {metadata.get('collection_host', 'Unknown')}\n")
                f.write(f"Collection User: {metadata.get('collection_user', 'Unknown')}\n")
                f.write(f"Artifact Count: {metadata.get('artifact_count', 0)}\n")
                f.write(f"Error Count: {len(metadata.get('errors', []))}\n")
                f.write(f"Checksum: {metadata.get('checksum', 'Unknown')}\n\n")
                
                f.write(f"Collected Artifacts:\n")
                f.write(f"{'-' * 20}\n")
                
                artifacts = data.get('artifacts', {})
                for collector, artifact_data in artifacts.items():
                    if isinstance(artifact_data, dict):
                        f.write(f"\n{collector}:\n")
                        # Count non-empty artifacts
                        count = 0
                        for key, value in artifact_data.items():
                            if value and key != 'errors':
                                count += 1
                        f.write(f"  - {count} artifact types collected\n")
                        
                        # List errors if any
                        if 'errors' in artifact_data and artifact_data['errors']:
                            f.write(f"  - {len(artifact_data['errors'])} errors encountered\n")
                
                # List all errors
                if metadata.get('errors'):
                    f.write(f"\n\nErrors Encountered:\n")
                    f.write(f"{'-' * 20}\n")
                    for error in metadata['errors']:
                        f.write(f"- [{error['collector']}] {error['error']}\n")
                
            self.logger.info(f"Saved summary to {filepath}")
        except Exception as e:
            self.logger.warning(f"Could not save summary: {str(e)}")
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"
    
    def load_from_local(self, filepath: str) -> Dict[str, Any]:
        """Load serialized artifacts from local storage"""
        try:
            if filepath.endswith('.gz'):
                with gzip.open(filepath, 'rt', encoding='utf-8') as f:
                    data = json.load(f)
            else:
                with open(filepath, 'r') as f:
                    data = json.load(f)
            
            # Verify checksum
            stored_checksum = data.get('metadata', {}).get('checksum')
            if stored_checksum:
                # Remove checksum before verification
                data_copy = json.loads(json.dumps(data))
                del data_copy['metadata']['checksum']
                
                json_str = json.dumps(data_copy, sort_keys=True, default=str)
                calculated_checksum = hashlib.sha256(json_str.encode()).hexdigest()
                
                if stored_checksum != calculated_checksum:
                    self.logger.warning("Checksum verification failed")
            
            return data
            
        except Exception as e:
            self.logger.error(f"Failed to load artifacts from {filepath}: {str(e)}")
            raise
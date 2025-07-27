#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Artifact Sender Module

This module handles sending collected forensic artifacts to a REST API server.
It supports both direct and chunked uploads, retry logic, and health checking.

Classes:
    ArtifactSender: Manages artifact transmission to API server

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import time
import requests
from typing import Dict, Any, Optional
import logging
from datetime import datetime


class ArtifactSender:
    """
    Handle sending artifacts to REST API server.
    
    This class provides functionality to:
    - Send artifacts to a REST API endpoint
    - Support chunked upload for large files
    - Implement retry logic with exponential backoff
    - Check server health before sending
    - Handle authentication via API keys
    - Track upload status
    
    Attributes:
        config (Dict[str, Any]): Configuration dictionary
        logger (logging.Logger): Logger instance
        api_url (str): Base URL of the API server
        api_key (str): API authentication key
        timeout (int): Request timeout in seconds
        retry_count (int): Number of retry attempts
        chunk_size (int): Size of chunks for large uploads
        session (requests.Session): HTTP session for connection pooling
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # API configuration
        api_config = config.get('api_server', {})
        self.api_url = api_config.get('url', 'https://forensics-api.example.com')
        self.api_key = api_config.get('api_key', '')
        self.timeout = api_config.get('timeout', 30)
        self.retry_count = api_config.get('retry_count', 3)
        self.chunk_size = api_config.get('chunk_size_mb', 10) * 1024 * 1024  # Convert to bytes
        
        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DockerForensics/2.0',
            'Content-Type': 'application/json'
        })
        
        if self.api_key:
            self.session.headers['Authorization'] = f'Bearer {self.api_key}'
    
    def send_artifacts(self, serialized_data: Dict[str, Any], 
                      local_file_path: Optional[str] = None) -> Dict[str, Any]:
        """Send artifacts to API server"""
        
        endpoint = f"{self.api_url}/api/v1/artifacts"
        
        # Prepare metadata for initial request
        metadata = {
            'container_id': serialized_data['metadata']['container_id'],
            'collection_timestamp': serialized_data['metadata']['collection_timestamp'],
            'collection_host': serialized_data['metadata']['collection_host'],
            'artifact_count': serialized_data['metadata']['artifact_count'],
            'checksum': serialized_data['metadata']['checksum'],
            'local_file_path': local_file_path
        }
        
        # Check if we need to chunk the data
        json_str = json.dumps(serialized_data)
        data_size = len(json_str.encode('utf-8'))
        
        if data_size > self.chunk_size:
            # Large file - use chunked upload
            return self._send_chunked(endpoint, serialized_data, metadata)
        else:
            # Small file - send directly
            return self._send_direct(endpoint, serialized_data, metadata)
    
    def _send_direct(self, endpoint: str, data: Dict[str, Any], 
                    metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Send artifacts directly in a single request"""
        
        for attempt in range(self.retry_count):
            try:
                self.logger.info(f"Sending artifacts to {endpoint} (attempt {attempt + 1}/{self.retry_count})")
                
                response = self.session.post(
                    endpoint,
                    json=data,
                    timeout=self.timeout
                )
                
                if response.status_code == 200 or response.status_code == 201:
                    result = response.json()
                    self.logger.info(f"Successfully sent artifacts. ID: {result.get('id', 'Unknown')}")
                    return {
                        'success': True,
                        'artifact_id': result.get('id'),
                        'message': result.get('message', 'Success'),
                        'response': result
                    }
                elif response.status_code == 401:
                    return {
                        'success': False,
                        'error': 'Authentication failed. Check API key.',
                        'status_code': response.status_code
                    }
                elif response.status_code == 413:
                    # Payload too large - try chunked upload
                    self.logger.warning("Payload too large, switching to chunked upload")
                    return self._send_chunked(endpoint, data, metadata)
                else:
                    error_msg = f"API returned status {response.status_code}: {response.text}"
                    self.logger.warning(error_msg)
                    
                    if attempt < self.retry_count - 1:
                        # Exponential backoff
                        wait_time = 2 ** attempt
                        self.logger.info(f"Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        return {
                            'success': False,
                            'error': error_msg,
                            'status_code': response.status_code
                        }
                        
            except requests.exceptions.Timeout:
                error_msg = f"Request timed out after {self.timeout} seconds"
                self.logger.warning(error_msg)
                
                if attempt < self.retry_count - 1:
                    time.sleep(2 ** attempt)
                else:
                    return {'success': False, 'error': error_msg}
                    
            except requests.exceptions.ConnectionError as e:
                error_msg = f"Connection error: {str(e)}"
                self.logger.warning(error_msg)
                
                if attempt < self.retry_count - 1:
                    time.sleep(2 ** attempt)
                else:
                    return {'success': False, 'error': error_msg}
                    
            except Exception as e:
                error_msg = f"Unexpected error: {str(e)}"
                self.logger.error(error_msg)
                return {'success': False, 'error': error_msg}
        
        return {'success': False, 'error': 'Max retries exceeded'}
    
    def _send_chunked(self, endpoint: str, data: Dict[str, Any], 
                     metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Send artifacts in chunks for large payloads"""
        
        try:
            # Initialize chunked upload
            init_endpoint = f"{endpoint}/chunked/init"
            init_response = self.session.post(
                init_endpoint,
                json={
                    'metadata': metadata,
                    'total_chunks': self._calculate_chunks(data)
                },
                timeout=self.timeout
            )
            
            if init_response.status_code != 200:
                return {
                    'success': False,
                    'error': f"Failed to initialize chunked upload: {init_response.text}"
                }
            
            upload_session = init_response.json()
            session_id = upload_session['session_id']
            
            # Send chunks
            json_str = json.dumps(data)
            chunks = self._split_into_chunks(json_str)
            
            for i, chunk in enumerate(chunks):
                chunk_endpoint = f"{endpoint}/chunked/{session_id}/chunk"
                chunk_response = self.session.post(
                    chunk_endpoint,
                    json={
                        'chunk_number': i,
                        'chunk_data': chunk,
                        'is_last': i == len(chunks) - 1
                    },
                    timeout=self.timeout
                )
                
                if chunk_response.status_code != 200:
                    return {
                        'success': False,
                        'error': f"Failed to upload chunk {i}: {chunk_response.text}"
                    }
                
                self.logger.info(f"Uploaded chunk {i + 1}/{len(chunks)}")
            
            # Finalize upload
            finalize_endpoint = f"{endpoint}/chunked/{session_id}/finalize"
            finalize_response = self.session.post(finalize_endpoint, timeout=self.timeout)
            
            if finalize_response.status_code == 200:
                result = finalize_response.json()
                self.logger.info(f"Successfully sent artifacts via chunked upload. ID: {result.get('id')}")
                return {
                    'success': True,
                    'artifact_id': result.get('id'),
                    'message': 'Chunked upload successful',
                    'response': result
                }
            else:
                return {
                    'success': False,
                    'error': f"Failed to finalize upload: {finalize_response.text}"
                }
                
        except Exception as e:
            error_msg = f"Chunked upload failed: {str(e)}"
            self.logger.error(error_msg)
            return {'success': False, 'error': error_msg}
    
    def _calculate_chunks(self, data: Dict[str, Any]) -> int:
        """Calculate number of chunks needed"""
        json_str = json.dumps(data)
        data_size = len(json_str.encode('utf-8'))
        return (data_size + self.chunk_size - 1) // self.chunk_size
    
    def _split_into_chunks(self, data_str: str) -> list:
        """Split data string into chunks"""
        encoded = data_str.encode('utf-8')
        chunks = []
        
        for i in range(0, len(encoded), self.chunk_size):
            chunk = encoded[i:i + self.chunk_size]
            # Base64 encode for safe transport
            import base64
            chunks.append(base64.b64encode(chunk).decode('utf-8'))
        
        return chunks
    
    def check_server_health(self) -> Dict[str, Any]:
        """Check if API server is healthy"""
        try:
            health_endpoint = f"{self.api_url}/api/v1/health"
            response = self.session.get(health_endpoint, timeout=5)
            
            if response.status_code == 200:
                return {
                    'healthy': True,
                    'server_info': response.json()
                }
            else:
                return {
                    'healthy': False,
                    'error': f"Server returned status {response.status_code}"
                }
        except Exception as e:
            return {
                'healthy': False,
                'error': str(e)
            }
    
    def get_artifact_status(self, artifact_id: str) -> Dict[str, Any]:
        """Get status of previously sent artifact"""
        try:
            status_endpoint = f"{self.api_url}/api/v1/artifacts/{artifact_id}"
            response = self.session.get(status_endpoint, timeout=self.timeout)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {
                    'error': f"Failed to get status: {response.status_code}"
                }
        except Exception as e:
            return {'error': str(e)}
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base Collector Module

This module provides the abstract base class for all artifact collectors in the
Docker Forensics framework. It defines the common interface and shared functionality
that all specific collectors must implement.

Classes:
    BaseCollector: Abstract base class for artifact collectors

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, Optional, List


class BaseCollector(ABC):
    """
    Abstract base class for all artifact collectors.
    
    This class provides common functionality for artifact collection including
    error handling, logging, and file saving capabilities. All specific collectors
    must inherit from this class and implement the collect() method.
    
    Attributes:
        container_id (str): The Docker container ID
        container_info (Dict[str, Any]): Container inspection data
        config (Dict[str, Any]): Configuration dictionary
        logger (logging.Logger): Logger instance for this collector
        artifacts (Dict[str, Any]): Collected artifacts storage
        errors (List[Dict[str, Any]]): List of errors encountered during collection
    """
    
    def __init__(self, container_id: str, container_info: Dict[str, Any], config: Dict[str, Any]):
        self.container_id = container_id
        self.container_info = container_info
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.artifacts = {}
        self.errors = []
        
    @abstractmethod
    def collect(self) -> Dict[str, Any]:
        """Collect artifacts - must be implemented by subclasses"""
        pass
    
    def save_artifact(self, artifact_type: str, data: Any, filename: Optional[str] = None) -> str:
        """Save artifact to file"""
        base_path = self.config['ARTIFACTS']['BASE_PATH'].format(self.container_id)
        
        if filename:
            filepath = os.path.join(base_path, filename)
        else:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(base_path, f"{artifact_type}_{timestamp}.json")
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        self.logger.info(f"Saved {artifact_type} to {filepath}")
        return filepath
    
    def add_error(self, error_msg: str) -> None:
        """Add error to collection errors"""
        self.errors.append({
            'timestamp': datetime.now().isoformat(),
            'collector': self.__class__.__name__,
            'error': error_msg
        })
        self.logger.error(error_msg)
    
    def get_container_pid(self) -> Optional[int]:
        """Get container PID from container info"""
        try:
            return self.container_info[0]['State']['Pid']
        except (KeyError, IndexError):
            self.add_error("Failed to get container PID")
            return None
    
    def get_storage_driver(self) -> Optional[str]:
        """Get storage driver type"""
        try:
            return self.container_info[0]['GraphDriver']['Name']
        except (KeyError, IndexError):
            self.add_error("Failed to get storage driver")
            return None
    
    def get_graph_driver_data(self) -> Dict[str, Any]:
        """Get graph driver data"""
        try:
            return self.container_info[0]['GraphDriver']['Data']
        except (KeyError, IndexError):
            self.add_error("Failed to get graph driver data")
            return {}
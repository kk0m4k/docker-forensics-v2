#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logging Configuration Module

This module provides centralized logging configuration for the Docker Forensics
framework, including console and file handlers with rotation support.

Functions:
    configure_logging: Set up logging configuration for the application

Author: Kim, Tae hoon (Francesco)
"""

import logging
from logging.handlers import RotatingFileHandler


def configure_logging(log_level=logging.INFO, log_file='debug.log', 
                     max_bytes=10*1024*1024, backup_count=5):
    """
    Configure logging for the application.
    
    Sets up both console and file logging with appropriate formatters
    and rotation for file logs.
    
    Args:
        log_level: Logging level (default: logging.INFO)
        log_file: Path to log file (default: 'debug.log')
        max_bytes: Maximum size of log file before rotation (default: 10MB)
        backup_count: Number of backup files to keep (default: 5)
        
    Returns:
        logging.Logger: Configured root logger
    """
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    
    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    root_logger.handlers = []
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Add file handler with rotation
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    return root_logger
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Authentication Module

This module provides authentication functionality for the Docker Forensics API,
including API key verification and JWT token management. It supports both simple
API key authentication and JWT-based authentication flows.

Functions:
    get_api_key: Retrieve API key from environment
    get_jwt_secret: Retrieve JWT secret from environment
    verify_api_key: Verify provided API key
    generate_token: Generate JWT token
    verify_token: Verify and decode JWT token
    hash_password: Hash password using SHA256
    verify_password: Verify password against hash

Author: Kim, Tae hoon (Francesco)
"""

import os
import hashlib
import secrets
from typing import Optional
from datetime import datetime, timedelta
import jwt


# Configuration
API_KEY_ENV = "FORENSICS_API_KEY"
JWT_SECRET_ENV = "FORENSICS_JWT_SECRET"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24


def get_api_key() -> Optional[str]:
    """
    Get API key from environment variable.
    
    Returns:
        Optional[str]: API key if set, None otherwise
    """
    return os.environ.get(API_KEY_ENV)


def get_jwt_secret() -> str:
    """Get JWT secret from environment or generate one"""
    secret = os.environ.get(JWT_SECRET_ENV)
    if not secret:
        # Generate a random secret if not provided
        secret = secrets.token_urlsafe(32)
    return secret


def verify_api_key(provided_key: str) -> bool:
    """Verify provided API key"""
    expected_key = get_api_key()
    
    if not expected_key:
        # No API key configured - allow access (for development)
        # In production, this should return False
        return True
    
    # Use constant-time comparison to prevent timing attacks
    return secrets.compare_digest(provided_key, expected_key)


def generate_token(user_id: str, additional_claims: Optional[dict] = None) -> str:
    """Generate JWT token"""
    payload = {
        "user_id": user_id,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow(),
        "iss": "docker-forensics-api"
    }
    
    if additional_claims:
        payload.update(additional_claims)
    
    token = jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)
    return token


def verify_token(token: str) -> Optional[dict]:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def hash_password(password: str) -> str:
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(provided_password: str, stored_hash: str) -> bool:
    """Verify password against stored hash"""
    provided_hash = hash_password(provided_password)
    return secrets.compare_digest(provided_hash, stored_hash)
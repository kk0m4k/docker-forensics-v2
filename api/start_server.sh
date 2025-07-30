#!/bin/bash

# Docker Forensics API Server Startup Script
# This script helps activate the correct environment and start the server

echo "🚀 Starting Docker Forensics API Server..."

# Check if pyenv is available
if command -v pyenv &> /dev/null; then
    echo "📦 Using pyenv environment..."
    
    # Check if docker-forensics environment exists
    if pyenv versions | grep -q "docker-forensics"; then
        echo "✅ Using docker-forensics environment..."
        export PYENV_VERSION=docker-forensics
    else
        echo "⚠️  docker-forensics environment not found. Using system Python..."
    fi
else
    echo "ℹ️  pyenv not found. Using system Python..."
fi

# Check if requirements are installed
echo "🔍 Checking dependencies..."
python -c "import aiofiles, fastapi, uvicorn" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "📥 Installing dependencies..."
    pip install -r ../requirements.txt
fi

# Start the server
echo "🌐 Starting server..."
python server.py "$@" 
# docker-forensics-v2
Enhanced Docker forensics tool for gathering artifacts from Docker containers, with support for JSON export and REST API integration.

## Features

### Core Artifacts
1. ✅ Whiteout: AUFS, Overlay/Overlay2
2. ✅ Binary and metadata of Process running within container
3. ✅ Result of *docker inspect command*
4. ✅ Container-specific files: *config.v2.json, hostconfig.json, hostname, resolv.conf, resolv.conf.hash*
5. ✅ Container logs: *container_id.json*
6. ✅ Docker daemon logs (Journald)
7. ✅ Hidden directories
8. ✅ Changed files or directories
9. ✅ Open ports and network sessions (using nsenter)
10. ✅ System datetime and uptime
11. ✅ Executable binaries/scripts created on Container Layer

### New Artifacts (v2)
#### Container Runtime
- Runtime state files (`/var/run/docker/runtime-runc/moby/*/state.json`)
- Mount information and checkpoint data
- Shared memory contents (`/shm/`)
- cgroup information (v1 and v2)

#### Security & Permissions
- AppArmor/SELinux profiles and contexts
- Seccomp profiles
- Container capabilities
- User/group information and `/etc/passwd`
- Security options

#### Network
- Docker network database (`local-kv.db`)
- iptables/nftables rules
- docker-proxy process information
- Network namespaces and veth pairs
- DNS configuration

#### Logging & Monitoring
- Container logs (JSON and recent)
- Journald logs
- Docker events
- Cached logs

#### Runtime Memory
- Process environment variables
- Command line arguments
- Open files (lsof)
- Memory mappings
- Process status

### New Features (v2)
- 📦 **JSON Serialization**: All artifacts saved in structured JSON format
- 🗜️ **Compression**: Optional gzip compression for storage efficiency
- 🌐 **REST API**: Send artifacts to centralized server
- 🔄 **Chunked Upload**: Support for large artifact files
- 🔐 **Authentication**: API key-based authentication
- 📊 **Local Storage**: Organized artifact storage with summaries

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/docker-forensics-v2.git
cd docker-forensics-v2

# Install dependencies
pip3 install -r requirements.txt

# Copy and configure settings
cp config.json.example config.json
# Edit config.json with your settings
```

## Configuration

Edit `config.json` to configure:

```json
{
    "ARTIFACTS": {
        "BASE_PATH": "./artifacts/{}",
        "EXECUTABLE_PATH": "BASE_PATH/executables/",
        "DIFF_FILES_PATH": "BASE_PATH/diff_files/",
        "LOG_JOURNALD_SERVICE": "TRUE"
    },
    "local_storage": {
        "path": "/var/docker-forensics/artifacts/",
        "max_size_mb": 1000,
        "compression": true
    },
    "api_server": {
        "url": "https://forensics-api.example.com",
        "timeout": 30,
        "retry_count": 3,
        "chunk_size_mb": 10
    }
}
```

## Usage

### Basic Collection (Local Storage Only)
```bash
sudo python3 df_v2.py -i CONTAINER_ID
```

### Send to API Server
```bash
sudo python3 df_v2.py -i CONTAINER_ID --send-api
```

### Both Local Storage and API
```bash
sudo python3 df_v2.py -i CONTAINER_ID --save-local --send-api
```


## API Server

### Starting the API Server
```bash
# Set environment variables
export JWT_SECRET_KEY="your-jwt-secret-key"
export JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30

# Run server
cd api
python3 server.py
```

### API Endpoints
- `POST /api/v1/auth/login` - Login and get JWT token
- `POST /api/v1/artifacts` - Submit artifacts (requires JWT)
- `GET /api/v1/artifacts/{id}` - Retrieve specific artifact (requires JWT)
- `GET /api/v1/artifacts` - List artifacts (requires JWT)
- `GET /api/v1/health` - Health check
- `DELETE /api/v1/artifacts/{id}` - Delete artifact (requires JWT)

### Using Docker
```bash
# Build API server image
docker build -t docker-forensics-api ./api

# Run API server
docker run -d \
  -p 8000:8000 \
  -e JWT_SECRET_KEY="your-jwt-secret-key" \
  -e JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30 \
  -v /var/docker-forensics/db:/var/docker-forensics/db \
  docker-forensics-api
```

## Output Format

### JSON Structure
```json
{
  "metadata": {
    "version": "2.0",
    "container_id": "abc123...",
    "collection_timestamp": "2024-01-20T10:30:00",
    "collection_host": "forensics-host",
    "checksum": "sha256...",
    "errors": []
  },
  "artifacts": {
    "core": { ... },
    "runtime": { ... },
    "security": { ... },
    "network": { ... },
    "logging": { ... },
    "memory": { ... }
  }
}
```

### Local Storage Structure
```
/var/docker-forensics/artifacts/
├── abc123/
│   ├── forensics_abc123_20240120_103000.json.gz
│   └── summary_abc123_20240120_103000.txt
└── def456/
    ├── forensics_def456_20240120_104500.json.gz
    └── summary_def456_20240120_104500.txt
```

## Requirements

- Python 3.7+
- Root privileges (for accessing Docker internals)
- Docker running on the system
- For API: FastAPI, uvicorn, aiofiles

## Security Considerations

1. **API Authentication**: JWT tokens expire after configured time (default 30 minutes)
2. **TLS/SSL**: Use HTTPS for API communication
3. **File Permissions**: Artifact files contain sensitive data
4. **Network Security**: Restrict API server access

## Development

### Running Tests
```bash
pytest tests/
```

### Code Style
```bash
black .
flake8 .
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure running with sudo/root privileges

2. **Container Not Found**
   - Verify container ID/name is correct
   - Check if container is running

3. **API Connection Failed**
   - Verify API server URL and connectivity
   - Check JWT token is valid and not expired
   - Obtain new token via /api/v1/auth/login endpoint

4. **Storage Full**
   - Check `max_size_mb` in configuration
   - Clean up old artifacts

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## License

[Your License Here]

## Acknowledgments

Based on the original docker-forensics project, enhanced with modern features for enterprise use.
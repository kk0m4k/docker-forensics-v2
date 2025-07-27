#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Docker Forensics v2 - Main Entry Point

This module serves as the main entry point for Docker forensics artifact collection.
It coordinates various collectors to gather comprehensive forensic data from Docker
containers and supports both local storage and remote API transmission.

Features:
    - Modular artifact collection architecture
    - JSON serialization with compression
    - REST API integration for centralized storage
    - Comprehensive artifact coverage including runtime, security, network, etc.

Author: Kim, Tae hoon (Francesco)
Version: 2.0.0
"""

import os
import sys
import json
import argparse
import logging
import subprocess
from datetime import datetime
from typing import Dict, Any, List

# Import utility modules
from utils.logging_config import configure_logging

# Import new modules
from modules.runtime_artifacts import RuntimeArtifactsCollector
from modules.security_artifacts import SecurityArtifactsCollector
from modules.network_artifacts import NetworkArtifactsCollector
from modules.logging_artifacts import LoggingArtifactsCollector
from modules.memory_artifacts import MemoryArtifactsCollector
from modules.storage_artifacts import StorageArtifactsCollector
from modules.image_artifacts import ImageArtifactsCollector
from modules.plugin_artifacts import PluginArtifactsCollector
from utils.artifact_serializer import ArtifactSerializer
from utils.artifact_sender import ArtifactSender


class DockerForensicsV2:
    """Enhanced Docker Forensics collector"""
    
    def __init__(self, container_id: str, config_path: str = "config.json"):
        self.container_id = container_id
        self.config = self._load_config(config_path)
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize components
        self.serializer = ArtifactSerializer(self.config)
        self.sender = ArtifactSender(self.config)
        
        # Container info will be populated after validation
        self.container_info = None
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration file"""
        if not os.path.exists(config_path):
            # Use default config
            return {
                "ARTIFACTS": {
                    "BASE_PATH": "./artifacts/{}",
                    "EXECUTABLE_PATH": "BASE_PATH/executables/",
                    "DIFF_FILES_PATH": "BASE_PATH/diff_files/",
                    "LOG_JOURNALD_SERVICE": "TRUE"
                },
                "SYSLOGSERVER": {
                    "HOST": "1.1.1.1",
                    "PORT": 514
                },
                "local_storage": {
                    "path": "/var/docker-forensics/artifacts/",
                    "max_size_mb": 1000,
                    "compression": True
                },
                "api_server": {
                    "url": "https://forensics-api.example.com",
                    "api_key": "",
                    "timeout": 30,
                    "retry_count": 3
                }
            }
        
        with open(config_path, 'r') as f:
            return json.load(f)
    
    def validate_prerequisites(self) -> bool:
        """Validate prerequisites before collection"""
        # Check root privileges
        if os.geteuid() != 0:
            self.logger.error("This script must be run with root privileges")
            return False
        
        # Validate container exists and get info
        try:
            cmd = ['docker', 'inspect', self.container_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.container_info = json.loads(result.stdout)
                if not self.container_info:
                    self.logger.error(f"Container {self.container_id} not found")
                    return False
            else:
                self.logger.error(f"Container {self.container_id} not found")
                return False
        except Exception as e:
            self.logger.error(f"Failed to inspect container: {str(e)}")
            return False
        
        return True
    
    def collect_basic_info(self) -> Dict[str, Any]:
        """Collect basic container information"""
        self.logger.info("Collecting basic container information...")
        
        basic_info = {
            'inspect': self.container_info,
            'container_id': self.container_id,
            'collection_timestamp': datetime.now().isoformat()
        }
        
        return basic_info
    
    def collect_enhanced_artifacts(self) -> Dict[str, Any]:
        """Collect enhanced artifacts using new modules"""
        self.logger.info("Collecting enhanced artifacts...")
        
        artifacts = {}
        errors = []
        
        # Initialize collectors
        collectors = [
            ('runtime', RuntimeArtifactsCollector),
            ('security', SecurityArtifactsCollector),
            ('network', NetworkArtifactsCollector),
            ('logging', LoggingArtifactsCollector),
            ('memory', MemoryArtifactsCollector),
            ('storage', StorageArtifactsCollector),
            ('image', ImageArtifactsCollector),
            ('plugin', PluginArtifactsCollector)
        ]
        
        for name, CollectorClass in collectors:
            try:
                self.logger.info(f"Running {name} collector...")
                collector = CollectorClass(self.container_id, self.container_info, self.config)
                artifacts[name] = collector.collect()
                
                # Collect any errors from the collector
                if hasattr(collector, 'errors') and collector.errors:
                    errors.extend(collector.errors)
                    
            except Exception as e:
                error_msg = f"Failed to run {name} collector: {str(e)}"
                self.logger.error(error_msg)
                errors.append({
                    'collector': name,
                    'error': error_msg,
                    'timestamp': datetime.now().isoformat()
                })
        
        # Add errors to artifacts
        if errors:
            artifacts['collection_errors'] = errors
        
        return artifacts
    
    def collect_all_artifacts(self) -> Dict[str, Any]:
        """Collect all artifacts"""
        all_artifacts = {}
        
        # Collect basic container info
        all_artifacts['basic_info'] = self.collect_basic_info()
        
        # Collect enhanced artifacts
        enhanced = self.collect_enhanced_artifacts()
        all_artifacts.update(enhanced)
        
        return all_artifacts
    
    def save_artifacts_local(self, artifacts: Dict[str, Any]) -> str:
        """Save artifacts to local storage"""
        self.logger.info("Saving artifacts to local storage...")
        
        # Serialize artifacts
        serialized = self.serializer.serialize_artifacts(self.container_id, artifacts)
        
        # Save to local storage
        filepath = self.serializer.save_to_local(self.container_id, serialized)
        
        return filepath
    
    def send_artifacts_to_api(self, artifacts: Dict[str, Any], local_path: str = None) -> Dict[str, Any]:
        """Send artifacts to API server"""
        self.logger.info("Sending artifacts to API server...")
        
        # Check server health first
        health = self.sender.check_server_health()
        if not health.get('healthy', False):
            self.logger.warning(f"API server is not healthy: {health.get('error', 'Unknown error')}")
            return {'success': False, 'error': 'API server is not healthy'}
        
        # Serialize artifacts
        serialized = self.serializer.serialize_artifacts(self.container_id, artifacts)
        
        # Send to API
        result = self.sender.send_artifacts(serialized, local_path)
        
        return result
    
    def run(self, save_local: bool = True, send_api: bool = False) -> Dict[str, Any]:
        """Main execution method"""
        self.logger.info(f"Starting Docker Forensics v2 for container {self.container_id}")
        
        # Validate prerequisites
        if not self.validate_prerequisites():
            return {'success': False, 'error': 'Prerequisites validation failed'}
        
        # Collect all artifacts
        artifacts = self.collect_all_artifacts()
        
        results = {
            'success': True,
            'container_id': self.container_id,
            'artifact_count': len(artifacts)
        }
        
        # Save locally if requested
        if save_local:
            try:
                local_path = self.save_artifacts_local(artifacts)
                results['local_path'] = local_path
                self.logger.info(f"Artifacts saved locally to: {local_path}")
            except Exception as e:
                self.logger.error(f"Failed to save artifacts locally: {str(e)}")
                results['local_save_error'] = str(e)
        
        # Send to API if requested
        if send_api:
            try:
                api_result = self.send_artifacts_to_api(
                    artifacts, 
                    results.get('local_path')
                )
                results['api_result'] = api_result
                
                if api_result.get('success'):
                    self.logger.info(f"Artifacts sent to API. ID: {api_result.get('artifact_id')}")
                else:
                    self.logger.error(f"Failed to send to API: {api_result.get('error')}")
            except Exception as e:
                self.logger.error(f"Failed to send artifacts to API: {str(e)}")
                results['api_send_error'] = str(e)
        
        self.logger.info("Docker Forensics v2 collection completed")
        return results


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Docker Forensics v2 - Enhanced artifact collection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect and save locally only (default)
  sudo python3 df_v2.py -i container_id
  
  # Collect and send to API server
  sudo python3 df_v2.py -i container_id --send-api
  
  # Collect, save locally, and send to API
  sudo python3 df_v2.py -i container_id --save-local --send-api
  
  # Use custom config file
  sudo python3 df_v2.py -i container_id -c custom_config.json
        """
    )
    
    parser.add_argument('-i', '--container-id', required=True,
                        help='Docker container ID or name')
    parser.add_argument('-c', '--config', default='config.json',
                        help='Configuration file path (default: config.json)')
    parser.add_argument('--save-local', action='store_true', default=True,
                        help='Save artifacts to local storage (default: True)')
    parser.add_argument('--no-save-local', action='store_false', dest='save_local',
                        help='Do not save artifacts locally')
    parser.add_argument('--send-api', action='store_true', default=False,
                        help='Send artifacts to API server')
    parser.add_argument('--debug', action='store_true',
                        help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.debug else logging.INFO
    configure_logging(log_level=log_level)
    
    # Run forensics collection
    try:
        forensics = DockerForensicsV2(args.container_id, args.config)
        results = forensics.run(
            save_local=args.save_local,
            send_api=args.send_api
        )
        
        # Print results summary
        print("\n" + "="*50)
        print("Docker Forensics v2 - Collection Summary")
        print("="*50)
        print(f"Container ID: {results.get('container_id')}")
        print(f"Success: {results.get('success')}")
        print(f"Artifacts Collected: {results.get('artifact_count', 0)}")
        
        if 'local_path' in results:
            print(f"Local Storage: {results['local_path']}")
        
        if 'api_result' in results and results['api_result'].get('success'):
            print(f"API Upload: Success (ID: {results['api_result'].get('artifact_id')})")
        elif 'api_result' in results:
            print(f"API Upload: Failed ({results['api_result'].get('error')})")
        
        if 'error' in results:
            print(f"Error: {results['error']}")
        
        print("="*50 + "\n")
        
        # Exit with appropriate code
        sys.exit(0 if results.get('success') else 1)
        
    except KeyboardInterrupt:
        print("\nCollection cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nFatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
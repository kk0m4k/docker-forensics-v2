#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Image Artifacts Collector Module

This module collects image and layer-related artifacts from Docker containers,
including image metadata, layer database information, build cache, and image
history.

Classes:
    ImageArtifactsCollector: Collects image-related forensic artifacts

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import subprocess
from typing import Dict, Any, List, Optional
from .base_collector import BaseCollector


class ImageArtifactsCollector(BaseCollector):
    """
    Collector for image and layer related artifacts.
    
    This collector gathers image-specific information including:
    - Detailed image information and metadata
    - Layer database content and structure
    - Repository information
    - BuildKit cache data
    - Image history
    - Image manifest (if available)
    """
    
    def collect(self) -> Dict[str, Any]:
        """Collect image and layer artifacts"""
        self.logger.info(f"Collecting image artifacts for container {self.container_id}")
        
        artifacts = {
            'container_id': self.container_id,
            'collection_time': self.get_current_time(),
            'image_info': self.collect_image_info(),
            'layer_db': self.collect_layer_db_info(),
            'repositories': self.collect_repositories_info(),
            'build_cache': self.collect_build_cache(),
            'image_history': self.collect_image_history(),
            'manifest': self.collect_image_manifest()
        }
        
        self.artifacts = artifacts
        return artifacts
    
    def get_current_time(self) -> str:
        """Get current time in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def collect_image_info(self) -> Dict[str, Any]:
        """Collect detailed image information"""
        image_info = {
            'image_id': None,
            'image_name': None,
            'image_tags': [],
            'image_digest': None,
            'image_details': None,
            'parent_image': None
        }
        
        try:
            if self.container_info:
                # Get image ID from container
                image_id = self.container_info[0].get('Image', '')
                if image_id:
                    image_info['image_id'] = image_id
                    
                    # Get detailed image information
                    cmd = ['docker', 'image', 'inspect', image_id]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        image_details = json.loads(result.stdout)
                        if image_details:
                            details = image_details[0]
                            image_info['image_details'] = details
                            image_info['image_tags'] = details.get('RepoTags', [])
                            image_info['image_digest'] = details.get('RepoDigests', [])
                            image_info['parent_image'] = details.get('Parent', '')
                            
                            # Extract important metadata
                            image_info['metadata'] = {
                                'created': details.get('Created'),
                                'docker_version': details.get('DockerVersion'),
                                'architecture': details.get('Architecture'),
                                'os': details.get('Os'),
                                'size': details.get('Size'),
                                'virtual_size': details.get('VirtualSize'),
                                'root_fs': details.get('RootFS', {})
                            }
            
            self.logger.info(f"Collected image info for {image_info.get('image_id', 'unknown')}")
        except Exception as e:
            self.add_error(f"Failed to collect image info: {str(e)}")
        
        return image_info
    
    def collect_layer_db_info(self) -> Dict[str, Any]:
        """Collect layer database information"""
        layer_db_info = {
            'layer_db_path': None,
            'layers': [],
            'layer_metadata': {},
            'content_stores': []
        }
        
        try:
            storage_driver = self.get_storage_driver()
            if not storage_driver:
                return layer_db_info
            
            # Layer database path
            layer_db_path = f"/var/lib/docker/image/{storage_driver}/layerdb"
            if os.path.exists(layer_db_path):
                layer_db_info['layer_db_path'] = layer_db_path
                
                # List all layers
                sha_dir = os.path.join(layer_db_path, "sha256")
                if os.path.exists(sha_dir):
                    for layer_id in os.listdir(sha_dir):
                        layer_path = os.path.join(sha_dir, layer_id)
                        if os.path.isdir(layer_path):
                            layer_info = {
                                'id': layer_id,
                                'files': []
                            }
                            
                            # Read layer metadata files
                            metadata_files = ['cache-id', 'diff', 'size', 'parent']
                            for meta_file in metadata_files:
                                meta_path = os.path.join(layer_path, meta_file)
                                if os.path.exists(meta_path):
                                    try:
                                        with open(meta_path, 'r') as f:
                                            content = f.read().strip()
                                            layer_info[meta_file] = content
                                            layer_info['files'].append(meta_file)
                                    except:
                                        pass
                            
                            # Check if this layer is related to our container's image
                            if self.container_info:
                                image_id = self.container_info[0].get('Image', '')
                                if image_id and self._is_layer_in_image(layer_id, image_id):
                                    layer_info['in_container_image'] = True
                                    layer_db_info['layers'].append(layer_info)
            
            # Content store
            content_store_path = f"/var/lib/docker/image/{storage_driver}/imagedb/content/sha256"
            if os.path.exists(content_store_path):
                for content_id in os.listdir(content_store_path):
                    if self.container_info:
                        image_id = self.container_info[0].get('Image', '')
                        if image_id and image_id.startswith(f"sha256:{content_id}"):
                            content_path = os.path.join(content_store_path, content_id)
                            if os.path.exists(content_path):
                                try:
                                    with open(content_path, 'r') as f:
                                        content_data = json.load(f)
                                    layer_db_info['content_stores'].append({
                                        'id': content_id,
                                        'path': content_path,
                                        'data': content_data
                                    })
                                except:
                                    pass
            
            if layer_db_info['layers']:
                self.logger.info(f"Collected {len(layer_db_info['layers'])} layers from layer database")
        except Exception as e:
            self.add_error(f"Failed to collect layer database info: {str(e)}")
        
        return layer_db_info
    
    def collect_repositories_info(self) -> Dict[str, Any]:
        """Collect repositories information"""
        repos_info = {
            'repositories_file': None,
            'repositories': {}
        }
        
        try:
            storage_driver = self.get_storage_driver()
            if not storage_driver:
                return repos_info
            
            # Repositories file path
            repos_file = f"/var/lib/docker/image/{storage_driver}/repositories.json"
            if os.path.exists(repos_file):
                repos_info['repositories_file'] = repos_file
                
                try:
                    with open(repos_file, 'r') as f:
                        repos_data = json.load(f)
                    
                    # Filter repositories related to our container's image
                    if self.container_info:
                        image_id = self.container_info[0].get('Image', '')
                        if image_id:
                            # Get all tags for this image
                            for repo_name, tags in repos_data.get('Repositories', {}).items():
                                for tag, tag_image_id in tags.items():
                                    if tag_image_id == image_id or f"sha256:{tag_image_id}" == image_id:
                                        if repo_name not in repos_info['repositories']:
                                            repos_info['repositories'][repo_name] = {}
                                        repos_info['repositories'][repo_name][tag] = tag_image_id
                except Exception as e:
                    self.logger.warning(f"Could not parse repositories.json: {str(e)}")
            
            self.logger.info(f"Collected repositories info: {len(repos_info['repositories'])} repositories")
        except Exception as e:
            self.add_error(f"Failed to collect repositories info: {str(e)}")
        
        return repos_info
    
    def collect_build_cache(self) -> Dict[str, Any]:
        """Collect Docker build cache information"""
        build_cache_info = {
            'buildkit_path': None,
            'buildkit_enabled': False,
            'cache_entries': []
        }
        
        try:
            # Check for BuildKit cache
            buildkit_path = "/var/lib/docker/buildkit"
            if os.path.exists(buildkit_path):
                build_cache_info['buildkit_path'] = buildkit_path
                build_cache_info['buildkit_enabled'] = True
                
                # List cache directories
                for item in os.listdir(buildkit_path):
                    item_path = os.path.join(buildkit_path, item)
                    if os.path.isdir(item_path):
                        cache_entry = {
                            'name': item,
                            'path': item_path,
                            'size': 0
                        }
                        
                        # Calculate size
                        try:
                            for root, dirs, files in os.walk(item_path):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    cache_entry['size'] += os.path.getsize(file_path)
                        except:
                            pass
                        
                        cache_entry['size_human'] = self._format_bytes(cache_entry['size'])
                        build_cache_info['cache_entries'].append(cache_entry)
            
            # Get build cache using docker command
            cmd = ['docker', 'builder', 'du', '--verbose']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                build_cache_info['builder_du_output'] = result.stdout
            
            if build_cache_info['buildkit_enabled']:
                self.logger.info("Collected BuildKit cache information")
        except Exception as e:
            self.add_error(f"Failed to collect build cache info: {str(e)}")
        
        return build_cache_info
    
    def collect_image_history(self) -> List[Dict[str, Any]]:
        """Collect image history"""
        history = []
        
        try:
            if self.container_info:
                image_id = self.container_info[0].get('Image', '')
                if image_id:
                    # Get image history
                    cmd = ['docker', 'history', '--no-trunc', '--format', '{{json .}}', image_id]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        for line in lines:
                            if line:
                                try:
                                    history_entry = json.loads(line)
                                    history.append(history_entry)
                                except json.JSONDecodeError:
                                    pass
                    
                    if history:
                        self.logger.info(f"Collected {len(history)} image history entries")
        except Exception as e:
            self.add_error(f"Failed to collect image history: {str(e)}")
        
        return history
    
    def collect_image_manifest(self) -> Dict[str, Any]:
        """Collect image manifest if available"""
        manifest_info = {
            'manifest': None,
            'config': None
        }
        
        try:
            if self.container_info:
                # Get image tags
                image_details = self.collect_image_info()
                image_tags = image_details.get('image_tags', [])
                
                if image_tags:
                    # Try to get manifest for the first tag
                    image_tag = image_tags[0]
                    
                    # Try docker manifest inspect (requires experimental features)
                    cmd = ['docker', 'manifest', 'inspect', image_tag]
                    result = subprocess.run(cmd, capture_output=True, text=True, env={**os.environ, 'DOCKER_CLI_EXPERIMENTAL': 'enabled'})
                    
                    if result.returncode == 0:
                        try:
                            manifest_info['manifest'] = json.loads(result.stdout)
                            self.logger.info("Collected image manifest")
                        except json.JSONDecodeError:
                            pass
        except Exception as e:
            self.logger.debug(f"Could not collect image manifest: {str(e)}")
        
        return manifest_info
    
    def _is_layer_in_image(self, layer_id: str, image_id: str) -> bool:
        """Check if a layer belongs to the specified image"""
        try:
            # Get image details to check layers
            cmd = ['docker', 'image', 'inspect', image_id, '--format', '{{json .RootFS.Layers}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                layers = json.loads(result.stdout)
                return any(layer_id in layer for layer in layers)
        except:
            pass
        
        return False
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
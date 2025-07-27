#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Storage Artifacts Collector Module

This module collects storage driver-specific artifacts from Docker containers,
supporting various storage drivers including Overlay2, AUFS, Device Mapper,
Btrfs, and ZFS. It also collects whiteout files that indicate deletions.

Classes:
    StorageArtifactsCollector: Collects storage-related forensic artifacts

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import subprocess
from typing import Dict, Any, List, Optional
from .base_collector import BaseCollector


class StorageArtifactsCollector(BaseCollector):
    """
    Collector for storage driver specific artifacts.
    
    This collector gathers storage-specific information including:
    - Storage driver status and configuration
    - Layer information and layer database
    - Whiteout files (.wh. prefix) indicating deletions
    - Driver-specific artifacts for:
        - Overlay/Overlay2 (upper/lower dirs, link files)
        - AUFS (diff/layers/mnt paths)
        - Device Mapper (metadata and device info)
        - Btrfs (subvolumes and snapshots)
        - ZFS (datasets and properties)
    """
    
    def collect(self) -> Dict[str, Any]:
        """Collect storage driver specific artifacts"""
        self.logger.info(f"Collecting storage artifacts for container {self.container_id}")
        
        storage_driver = self.get_storage_driver()
        self.logger.info(f"Storage driver: {storage_driver}")
        
        artifacts = {
            'container_id': self.container_id,
            'collection_time': self.get_current_time(),
            'storage_driver': storage_driver,
            'driver_status': self.collect_driver_status(),
            'layer_info': self.collect_layer_info(),
            'whiteout_files': self.collect_whiteout_files()
        }
        
        # Collect driver-specific artifacts
        if storage_driver == 'overlay2':
            artifacts['overlay2'] = self.collect_overlay2_artifacts()
        elif storage_driver == 'overlay':
            artifacts['overlay'] = self.collect_overlay_artifacts()
        elif storage_driver == 'aufs':
            artifacts['aufs'] = self.collect_aufs_artifacts()
        elif storage_driver == 'devicemapper':
            artifacts['devicemapper'] = self.collect_devicemapper_artifacts()
        elif storage_driver == 'btrfs':
            artifacts['btrfs'] = self.collect_btrfs_artifacts()
        elif storage_driver == 'zfs':
            artifacts['zfs'] = self.collect_zfs_artifacts()
        else:
            self.logger.warning(f"Unknown or unsupported storage driver: {storage_driver}")
        
        self.artifacts = artifacts
        return artifacts
    
    def get_current_time(self) -> str:
        """Get current time in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def collect_driver_status(self) -> Dict[str, Any]:
        """Collect Docker storage driver status"""
        driver_status = {}
        
        try:
            # Get docker info
            cmd = ['docker', 'info', '--format', '{{json .}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                info = json.loads(result.stdout)
                driver_status = {
                    'driver': info.get('Driver'),
                    'driver_status': info.get('DriverStatus', []),
                    'docker_root_dir': info.get('DockerRootDir'),
                    'backing_filesystem': None
                }
                
                # Extract backing filesystem from driver status
                for status_item in info.get('DriverStatus', []):
                    if len(status_item) == 2:
                        if 'Backing Filesystem' in status_item[0]:
                            driver_status['backing_filesystem'] = status_item[1]
                        elif 'Pool Name' in status_item[0]:
                            driver_status['pool_name'] = status_item[1]
                        elif 'Data file' in status_item[0]:
                            driver_status['data_file'] = status_item[1]
                
            self.logger.info("Collected storage driver status")
        except Exception as e:
            self.add_error(f"Failed to collect driver status: {str(e)}")
        
        return driver_status
    
    def collect_layer_info(self) -> Dict[str, Any]:
        """Collect container layer information"""
        layer_info = {
            'layers': [],
            'layer_db_path': None,
            'size_info': {}
        }
        
        try:
            # Get image layers
            if self.container_info:
                image_id = self.container_info[0].get('Image', '')
                if image_id:
                    # Get layer information from image
                    cmd = ['docker', 'image', 'inspect', image_id]
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        image_info = json.loads(result.stdout)
                        if image_info:
                            layer_info['layers'] = image_info[0].get('RootFS', {}).get('Layers', [])
                            layer_info['image_id'] = image_id
            
            # Get layer database information
            layer_db_base = "/var/lib/docker/image"
            storage_driver = self.get_storage_driver()
            
            if storage_driver:
                layer_db_path = os.path.join(layer_db_base, storage_driver, "layerdb")
                if os.path.exists(layer_db_path):
                    layer_info['layer_db_path'] = layer_db_path
                    
                    # Count layers
                    sha_dir = os.path.join(layer_db_path, "sha256")
                    if os.path.exists(sha_dir):
                        layer_count = len([d for d in os.listdir(sha_dir) if os.path.isdir(os.path.join(sha_dir, d))])
                        layer_info['layer_count'] = layer_count
            
            # Get container layer size
            cmd = ['docker', 'ps', '-s', '--format', 'table {{.ID}}\t{{.Size}}', '--no-trunc']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header
                    parts = line.split('\t')
                    if len(parts) >= 2 and self.container_id.startswith(parts[0]):
                        layer_info['size_info']['container_size'] = parts[1]
                        break
            
            self.logger.info(f"Collected layer information: {len(layer_info['layers'])} layers")
        except Exception as e:
            self.add_error(f"Failed to collect layer info: {str(e)}")
        
        return layer_info
    
    def collect_whiteout_files(self) -> List[Dict[str, Any]]:
        """Collect whiteout files (deleted files markers)"""
        whiteout_files = []
        
        try:
            driver_data = self.get_graph_driver_data()
            storage_driver = self.get_storage_driver()
            
            search_paths = []
            
            if storage_driver in ['overlay', 'overlay2']:
                upper_dir = driver_data.get('UpperDir')
                if upper_dir and os.path.exists(upper_dir):
                    search_paths.append(upper_dir)
            elif storage_driver == 'aufs':
                # For AUFS, search in diff directories
                aufs_diff = f"/var/lib/docker/aufs/diff/{self.container_id}"
                if os.path.exists(aufs_diff):
                    search_paths.append(aufs_diff)
            
            # Search for whiteout files
            for search_path in search_paths:
                for root, dirs, files in os.walk(search_path):
                    for file in files:
                        if file.startswith('.wh.'):
                            whiteout_info = {
                                'path': os.path.join(root, file),
                                'relative_path': os.path.relpath(os.path.join(root, file), search_path),
                                'deleted_file': file[4:],  # Remove .wh. prefix
                                'type': 'file'
                            }
                            whiteout_files.append(whiteout_info)
                    
                    # Check for opaque directories
                    for dir_name in dirs:
                        if dir_name == '.wh..wh..opq':
                            whiteout_info = {
                                'path': os.path.join(root, dir_name),
                                'relative_path': os.path.relpath(root, search_path),
                                'type': 'opaque_directory'
                            }
                            whiteout_files.append(whiteout_info)
            
            if whiteout_files:
                self.logger.info(f"Found {len(whiteout_files)} whiteout files")
        except Exception as e:
            self.add_error(f"Failed to collect whiteout files: {str(e)}")
        
        return whiteout_files
    
    def collect_overlay2_artifacts(self) -> Dict[str, Any]:
        """Collect Overlay2 specific artifacts"""
        overlay2_data = {
            'upper_dir': None,
            'lower_dirs': [],
            'merged_dir': None,
            'work_dir': None,
            'link_file': None,
            'lower_file': None,
            'diff_dirs': []
        }
        
        try:
            driver_data = self.get_graph_driver_data()
            
            # Basic directories
            overlay2_data['upper_dir'] = driver_data.get('UpperDir')
            overlay2_data['merged_dir'] = driver_data.get('MergedDir')
            overlay2_data['work_dir'] = driver_data.get('WorkDir')
            
            # Parse lower dirs
            lower_dir_str = driver_data.get('LowerDir', '')
            if lower_dir_str:
                overlay2_data['lower_dirs'] = lower_dir_str.split(':')
            
            # Get container's overlay2 directory
            container_overlay_dir = f"/var/lib/docker/overlay2/{self.container_id}"
            if not os.path.exists(container_overlay_dir):
                # Try to find it by checking link files
                overlay2_root = "/var/lib/docker/overlay2"
                if os.path.exists(overlay2_root):
                    for item in os.listdir(overlay2_root):
                        item_path = os.path.join(overlay2_root, item)
                        if os.path.isdir(item_path):
                            # Check if this directory belongs to our container
                            if overlay2_data['upper_dir'] and overlay2_data['upper_dir'].startswith(item_path):
                                container_overlay_dir = item_path
                                break
            
            if os.path.exists(container_overlay_dir):
                # Read link file
                link_file = os.path.join(container_overlay_dir, "link")
                if os.path.exists(link_file):
                    with open(link_file, 'r') as f:
                        overlay2_data['link_file'] = f.read().strip()
                
                # Read lower file
                lower_file = os.path.join(container_overlay_dir, "lower")
                if os.path.exists(lower_file):
                    with open(lower_file, 'r') as f:
                        overlay2_data['lower_file'] = f.read().strip()
                
                # List diff directory contents
                diff_dir = os.path.join(container_overlay_dir, "diff")
                if os.path.exists(diff_dir):
                    try:
                        # Get directory stats
                        total_size = 0
                        file_count = 0
                        for root, dirs, files in os.walk(diff_dir):
                            file_count += len(files)
                            for file in files:
                                try:
                                    file_path = os.path.join(root, file)
                                    total_size += os.path.getsize(file_path)
                                except:
                                    pass
                        
                        overlay2_data['diff_stats'] = {
                            'total_files': file_count,
                            'total_size': total_size,
                            'total_size_human': self._format_bytes(total_size)
                        }
                    except:
                        pass
            
            self.logger.info("Collected Overlay2 specific artifacts")
        except Exception as e:
            self.add_error(f"Failed to collect Overlay2 artifacts: {str(e)}")
        
        return overlay2_data
    
    def collect_overlay_artifacts(self) -> Dict[str, Any]:
        """Collect Overlay specific artifacts (similar to Overlay2 but simpler)"""
        return self.collect_overlay2_artifacts()  # Similar structure
    
    def collect_aufs_artifacts(self) -> Dict[str, Any]:
        """Collect AUFS specific artifacts"""
        aufs_data = {
            'diff_path': None,
            'layers_path': None,
            'mnt_path': None,
            'layers': []
        }
        
        try:
            # AUFS paths
            aufs_data['diff_path'] = f"/var/lib/docker/aufs/diff/{self.container_id}"
            aufs_data['mnt_path'] = f"/var/lib/docker/aufs/mnt/{self.container_id}"
            
            # Read layers file
            layers_file = f"/var/lib/docker/aufs/layers/{self.container_id}"
            if os.path.exists(layers_file):
                aufs_data['layers_path'] = layers_file
                with open(layers_file, 'r') as f:
                    aufs_data['layers'] = [line.strip() for line in f if line.strip()]
            
            # Check if paths exist
            for key in ['diff_path', 'mnt_path']:
                if aufs_data[key] and os.path.exists(aufs_data[key]):
                    aufs_data[f'{key}_exists'] = True
                else:
                    aufs_data[f'{key}_exists'] = False
            
            self.logger.info("Collected AUFS specific artifacts")
        except Exception as e:
            self.add_error(f"Failed to collect AUFS artifacts: {str(e)}")
        
        return aufs_data
    
    def collect_devicemapper_artifacts(self) -> Dict[str, Any]:
        """Collect Device Mapper specific artifacts"""
        dm_data = {
            'metadata_path': None,
            'devicemapper_path': None,
            'device_info': {}
        }
        
        try:
            # Device Mapper paths
            dm_base = "/var/lib/docker/devicemapper"
            if os.path.exists(dm_base):
                dm_data['devicemapper_path'] = dm_base
                
                # Metadata path
                metadata_path = os.path.join(dm_base, "metadata", self.container_id)
                if os.path.exists(metadata_path):
                    dm_data['metadata_path'] = metadata_path
                    
                    # Read metadata
                    try:
                        with open(metadata_path, 'r') as f:
                            dm_data['metadata'] = json.load(f)
                    except:
                        pass
            
            # Get device mapper status
            cmd = ['dmsetup', 'status']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if f"docker-{self.container_id[:12]}" in line:
                        dm_data['device_info']['status'] = line
                        break
            
            self.logger.info("Collected Device Mapper specific artifacts")
        except Exception as e:
            self.add_error(f"Failed to collect Device Mapper artifacts: {str(e)}")
        
        return dm_data
    
    def collect_btrfs_artifacts(self) -> Dict[str, Any]:
        """Collect Btrfs specific artifacts"""
        btrfs_data = {
            'subvolumes': [],
            'snapshots': []
        }
        
        try:
            # Check if btrfs is available
            result = subprocess.run(['which', 'btrfs'], capture_output=True)
            if result.returncode != 0:
                self.logger.warning("btrfs command not available")
                return btrfs_data
            
            # Get subvolume list
            docker_root = "/var/lib/docker"
            cmd = ['btrfs', 'subvolume', 'list', docker_root]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if self.container_id[:12] in line:
                        btrfs_data['subvolumes'].append(line)
            
            # Get snapshot information
            cmd = ['btrfs', 'subvolume', 'show', f"{docker_root}/btrfs/subvolumes/{self.container_id}"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                btrfs_data['subvolume_info'] = result.stdout
            
            self.logger.info("Collected Btrfs specific artifacts")
        except Exception as e:
            self.add_error(f"Failed to collect Btrfs artifacts: {str(e)}")
        
        return btrfs_data
    
    def collect_zfs_artifacts(self) -> Dict[str, Any]:
        """Collect ZFS specific artifacts"""
        zfs_data = {
            'datasets': [],
            'snapshots': [],
            'properties': {}
        }
        
        try:
            # Check if zfs is available
            result = subprocess.run(['which', 'zfs'], capture_output=True)
            if result.returncode != 0:
                self.logger.warning("zfs command not available")
                return zfs_data
            
            # Get dataset list
            cmd = ['zfs', 'list', '-H', '-o', 'name']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if 'docker' in line and self.container_id[:12] in line:
                        zfs_data['datasets'].append(line)
                        
                        # Get dataset properties
                        prop_cmd = ['zfs', 'get', 'all', line, '-H']
                        prop_result = subprocess.run(prop_cmd, capture_output=True, text=True)
                        
                        if prop_result.returncode == 0:
                            properties = {}
                            for prop_line in prop_result.stdout.strip().split('\n'):
                                parts = prop_line.split('\t')
                                if len(parts) >= 3:
                                    properties[parts[1]] = parts[2]
                            zfs_data['properties'][line] = properties
            
            # Get snapshots
            cmd = ['zfs', 'list', '-t', 'snapshot', '-H', '-o', 'name']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if self.container_id[:12] in line:
                        zfs_data['snapshots'].append(line)
            
            self.logger.info("Collected ZFS specific artifacts")
        except Exception as e:
            self.add_error(f"Failed to collect ZFS artifacts: {str(e)}")
        
        return zfs_data
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
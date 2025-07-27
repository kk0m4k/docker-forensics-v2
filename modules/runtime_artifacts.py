#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Runtime Artifacts Collector Module

This module is responsible for collecting runtime-related artifacts from Docker
containers, including runtime state, mount information, checkpoints, cgroup data,
system information, and file changes.

Classes:
    RuntimeArtifactsCollector: Collects runtime-specific forensic artifacts

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import subprocess
from typing import Dict, Any, List, Optional
from .base_collector import BaseCollector


class RuntimeArtifactsCollector(BaseCollector):
    """
    Collector for container runtime artifacts.
    
    This collector gathers runtime-specific information including:
    - Container runtime state from runc
    - Mount points and mount information
    - Checkpoint data (if CRIU is used)
    - Container state details
    - Shared memory contents
    - Cgroup configuration (v1 and v2)
    - System time and uptime
    - Changed files (docker diff)
    """
    
    def collect(self) -> Dict[str, Any]:
        """Collect runtime artifacts"""
        self.logger.info(f"Collecting runtime artifacts for container {self.container_id}")
        
        artifacts = {
            'container_id': self.container_id,
            'collection_time': self.get_current_time(),
            'runtime_state': self.collect_runtime_state(),
            'mounts': self.collect_mount_info(),
            'checkpoints': self.collect_checkpoints(),
            'container_state': self.collect_container_state(),
            'shm_contents': self.collect_shm_contents(),
            'cgroup_info': self.collect_cgroup_info(),
            'system_info': self.collect_system_info(),
            'changed_files': self.collect_changed_files()
        }
        
        self.artifacts = artifacts
        return artifacts
    
    def get_current_time(self) -> str:
        """Get current time in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def collect_runtime_state(self) -> Optional[Dict[str, Any]]:
        """Collect runtime state from /var/run/docker/runtime-runc/moby/*/state.json"""
        runtime_base = "/var/run/docker/runtime-runc/moby"
        state_data = {}
        
        try:
            if os.path.exists(runtime_base):
                container_runtime_path = os.path.join(runtime_base, self.container_id)
                state_file = os.path.join(container_runtime_path, "state.json")
                
                if os.path.exists(state_file):
                    with open(state_file, 'r') as f:
                        state_data = json.load(f)
                    self.logger.info(f"Collected runtime state from {state_file}")
                else:
                    self.logger.warning(f"Runtime state file not found: {state_file}")
        except Exception as e:
            self.add_error(f"Failed to collect runtime state: {str(e)}")
        
        return state_data
    
    def collect_mount_info(self) -> List[Dict[str, Any]]:
        """Collect mount information"""
        mounts = []
        mounts_file = f"/var/lib/docker/containers/{self.container_id}/mounts"
        
        try:
            if os.path.exists(mounts_file):
                with open(mounts_file, 'r') as f:
                    mounts_data = f.read()
                if mounts_data.strip():
                    mounts = json.loads(mounts_data)
                self.logger.info(f"Collected mount info from {mounts_file}")
            
            # Also collect from /proc/mounts for the container
            pid = self.get_container_pid()
            if pid:
                proc_mounts = f"/proc/{pid}/mounts"
                if os.path.exists(proc_mounts):
                    with open(proc_mounts, 'r') as f:
                        proc_mount_data = []
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 4:
                                proc_mount_data.append({
                                    'device': parts[0],
                                    'mount_point': parts[1],
                                    'fs_type': parts[2],
                                    'options': parts[3] if len(parts) > 3 else ''
                                })
                        if proc_mount_data:
                            mounts.append({'source': 'proc_mounts', 'mounts': proc_mount_data})
        except Exception as e:
            self.add_error(f"Failed to collect mount info: {str(e)}")
        
        return mounts
    
    def collect_checkpoints(self) -> List[Dict[str, Any]]:
        """Collect checkpoint data if exists (CRIU)"""
        checkpoints = []
        checkpoint_dir = f"/var/lib/docker/containers/{self.container_id}/checkpoints"
        
        try:
            if os.path.exists(checkpoint_dir):
                for checkpoint in os.listdir(checkpoint_dir):
                    checkpoint_path = os.path.join(checkpoint_dir, checkpoint)
                    checkpoint_info = {
                        'name': checkpoint,
                        'path': checkpoint_path,
                        'files': []
                    }
                    
                    if os.path.isdir(checkpoint_path):
                        checkpoint_info['files'] = os.listdir(checkpoint_path)
                    
                    checkpoints.append(checkpoint_info)
                
                if checkpoints:
                    self.logger.info(f"Found {len(checkpoints)} checkpoints")
        except Exception as e:
            self.add_error(f"Failed to collect checkpoints: {str(e)}")
        
        return checkpoints
    
    def collect_container_state(self) -> Dict[str, Any]:
        """Collect detailed container state using docker inspect"""
        state = {}
        
        try:
            # Get current container state
            cmd = ['docker', 'inspect', '--format', '{{json .State}}', self.container_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                state = json.loads(result.stdout.strip())
                self.logger.info("Collected container state information")
        except Exception as e:
            self.add_error(f"Failed to collect container state: {str(e)}")
        
        return state
    
    def collect_shm_contents(self) -> Dict[str, Any]:
        """Collect shared memory contents"""
        shm_data = {
            'files': [],
            'total_size': 0
        }
        
        shm_path = f"/var/lib/docker/containers/{self.container_id}/mounts/shm"
        alt_shm_path = f"/var/lib/docker/containers/{self.container_id}/shm"
        
        for path in [shm_path, alt_shm_path]:
            try:
                if os.path.exists(path):
                    for item in os.listdir(path):
                        item_path = os.path.join(path, item)
                        stat = os.stat(item_path)
                        shm_data['files'].append({
                            'name': item,
                            'size': stat.st_size,
                            'mode': oct(stat.st_mode),
                            'uid': stat.st_uid,
                            'gid': stat.st_gid,
                            'mtime': stat.st_mtime
                        })
                        shm_data['total_size'] += stat.st_size
                    
                    if shm_data['files']:
                        self.logger.info(f"Collected {len(shm_data['files'])} files from shared memory")
                    break
            except Exception as e:
                self.add_error(f"Failed to collect shm contents from {path}: {str(e)}")
        
        return shm_data
    
    def collect_cgroup_info(self) -> Dict[str, Any]:
        """Collect cgroup information"""
        cgroup_data = {}
        
        # Cgroup v1 paths
        cgroup_v1_controllers = ['memory', 'cpu', 'cpuacct', 'blkio', 'devices', 'pids']
        
        # Cgroup v2 path
        cgroup_v2_path = f"/sys/fs/cgroup/system.slice/docker-{self.container_id}.scope"
        
        # Try cgroup v2 first
        try:
            if os.path.exists(cgroup_v2_path):
                cgroup_data['version'] = 'v2'
                cgroup_data['path'] = cgroup_v2_path
                cgroup_data['controllers'] = {}
                
                # Read important cgroup v2 files
                v2_files = ['cgroup.controllers', 'cgroup.stat', 'memory.current', 
                           'memory.stat', 'cpu.stat', 'pids.current']
                
                for file in v2_files:
                    file_path = os.path.join(cgroup_v2_path, file)
                    if os.path.exists(file_path):
                        try:
                            with open(file_path, 'r') as f:
                                cgroup_data['controllers'][file] = f.read().strip()
                        except:
                            pass
            else:
                # Try cgroup v1
                cgroup_data['version'] = 'v1'
                cgroup_data['controllers'] = {}
                
                for controller in cgroup_v1_controllers:
                    controller_path = f"/sys/fs/cgroup/{controller}/docker/{self.container_id}"
                    if os.path.exists(controller_path):
                        cgroup_data['controllers'][controller] = {
                            'path': controller_path
                        }
                        
                        # Read some important files based on controller
                        if controller == 'memory':
                            files = ['memory.usage_in_bytes', 'memory.limit_in_bytes', 'memory.stat']
                        elif controller == 'cpu':
                            files = ['cpu.shares', 'cpu.cfs_quota_us', 'cpu.cfs_period_us']
                        elif controller == 'pids':
                            files = ['pids.current', 'pids.max']
                        else:
                            files = []
                        
                        for file in files:
                            file_path = os.path.join(controller_path, file)
                            if os.path.exists(file_path):
                                try:
                                    with open(file_path, 'r') as f:
                                        cgroup_data['controllers'][controller][file] = f.read().strip()
                                except:
                                    pass
            
            if cgroup_data.get('controllers'):
                self.logger.info(f"Collected cgroup {cgroup_data.get('version', 'unknown')} information")
        except Exception as e:
            self.add_error(f"Failed to collect cgroup info: {str(e)}")
        
        return cgroup_data
    
    def collect_system_info(self) -> Dict[str, Any]:
        """Collect system time and uptime information"""
        system_info = {}
        
        try:
            # Get current system time
            cmd = ['date', '+%Y-%m-%d %H:%M:%S %Z']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                system_info['system_time'] = result.stdout.strip()
            
            # Get system uptime
            cmd = ['uptime']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                system_info['uptime'] = result.stdout.strip()
            
            # Get boot time
            cmd = ['who', '-b']
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                system_info['boot_time'] = result.stdout.strip()
            
            self.logger.info("Collected system information")
        except Exception as e:
            self.add_error(f"Failed to collect system info: {str(e)}")
        
        return system_info
    
    def collect_changed_files(self) -> List[Dict[str, Any]]:
        """Collect changed files using docker diff"""
        changed_files = []
        
        try:
            cmd = ['docker', 'diff', self.container_id]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line:
                        change_type = line[0]
                        path = line[2:] if len(line) > 2 else ''
                        
                        change_map = {
                            'A': 'Added',
                            'C': 'Changed',
                            'D': 'Deleted'
                        }
                        
                        changed_files.append({
                            'type': change_type,
                            'type_desc': change_map.get(change_type, 'Unknown'),
                            'path': path
                        })
                
                if changed_files:
                    self.logger.info(f"Collected {len(changed_files)} changed files")
        except Exception as e:
            self.add_error(f"Failed to collect changed files: {str(e)}")
        
        return changed_files
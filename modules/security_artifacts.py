#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Security Artifacts Collector Module

This module collects security and permission-related artifacts from Docker containers,
including AppArmor/SELinux profiles, capabilities, user information, and security
configurations.

Classes:
    SecurityArtifactsCollector: Collects security-related forensic artifacts

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import subprocess
from typing import Dict, Any, List, Optional
from .base_collector import BaseCollector


class SecurityArtifactsCollector(BaseCollector):
    """
    Collector for security and permission related artifacts.
    
    This collector gathers security-specific information including:
    - Container hosts file and permissions
    - AppArmor profiles and status
    - SELinux contexts and labels
    - Seccomp profiles
    - Linux capabilities (added/dropped)
    - User and group information
    - Security options from container configuration
    """
    
    def collect(self) -> Dict[str, Any]:
        """Collect security artifacts"""
        self.logger.info(f"Collecting security artifacts for container {self.container_id}")
        
        artifacts = {
            'container_id': self.container_id,
            'collection_time': self.get_current_time(),
            'hosts_file': self.collect_hosts_file(),
            'apparmor_profile': self.collect_apparmor_profile(),
            'selinux_context': self.collect_selinux_context(),
            'seccomp_profile': self.collect_seccomp_profile(),
            'capabilities': self.collect_capabilities(),
            'user_info': self.collect_user_info(),
            'security_opts': self.collect_security_opts()
        }
        
        self.artifacts = artifacts
        return artifacts
    
    def get_current_time(self) -> str:
        """Get current time in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def collect_hosts_file(self) -> Dict[str, Any]:
        """Collect container's hosts file"""
        hosts_data = {
            'path': None,
            'content': None,
            'permissions': None
        }
        
        hosts_path = f"/var/lib/docker/containers/{self.container_id}/hosts"
        
        try:
            if os.path.exists(hosts_path):
                hosts_data['path'] = hosts_path
                
                # Get file permissions
                stat = os.stat(hosts_path)
                hosts_data['permissions'] = {
                    'mode': oct(stat.st_mode),
                    'uid': stat.st_uid,
                    'gid': stat.st_gid,
                    'size': stat.st_size,
                    'mtime': stat.st_mtime
                }
                
                # Read content
                with open(hosts_path, 'r') as f:
                    hosts_data['content'] = f.read()
                
                self.logger.info(f"Collected hosts file from {hosts_path}")
        except Exception as e:
            self.add_error(f"Failed to collect hosts file: {str(e)}")
        
        return hosts_data
    
    def collect_apparmor_profile(self) -> Dict[str, Any]:
        """Collect AppArmor profile information"""
        apparmor_data = {
            'profile': None,
            'mode': None,
            'docker_default': None
        }
        
        try:
            # Get AppArmor profile from container config
            if self.container_info:
                apparmor_profile = self.container_info[0].get('AppArmorProfile', '')
                if apparmor_profile:
                    apparmor_data['profile'] = apparmor_profile
                
                # Check if it's using host config
                host_config = self.container_info[0].get('HostConfig', {})
                security_opt = host_config.get('SecurityOpt', [])
                for opt in security_opt:
                    if 'apparmor' in opt:
                        apparmor_data['security_opt'] = opt
            
            # Check Docker default AppArmor profile
            docker_apparmor_path = "/etc/apparmor.d/docker"
            if os.path.exists(docker_apparmor_path):
                apparmor_data['docker_default'] = True
                
                # Try to get profile status
                try:
                    result = subprocess.run(['aa-status', '--json'], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        status = json.loads(result.stdout)
                        # Look for docker-related profiles
                        for profile in status.get('profiles', {}).keys():
                            if 'docker' in profile.lower():
                                apparmor_data['active_profiles'] = apparmor_data.get('active_profiles', [])
                                apparmor_data['active_profiles'].append(profile)
                except:
                    pass
            
            if apparmor_data['profile']:
                self.logger.info(f"Collected AppArmor profile: {apparmor_data['profile']}")
        except Exception as e:
            self.add_error(f"Failed to collect AppArmor profile: {str(e)}")
        
        return apparmor_data
    
    def collect_selinux_context(self) -> Dict[str, Any]:
        """Collect SELinux context information"""
        selinux_data = {
            'enabled': False,
            'context': None,
            'mount_label': None,
            'process_label': None
        }
        
        try:
            # Check if SELinux is enabled
            if os.path.exists('/sys/fs/selinux'):
                selinux_data['enabled'] = True
                
                # Get SELinux context from container info
                if self.container_info:
                    mount_label = self.container_info[0].get('MountLabel', '')
                    process_label = self.container_info[0].get('ProcessLabel', '')
                    
                    if mount_label:
                        selinux_data['mount_label'] = mount_label
                    if process_label:
                        selinux_data['process_label'] = process_label
                
                # Try to get context for container process
                pid = self.get_container_pid()
                if pid:
                    try:
                        result = subprocess.run(['ps', '-Z', '-p', str(pid)], 
                                              capture_output=True, text=True)
                        if result.returncode == 0:
                            lines = result.stdout.strip().split('\n')
                            if len(lines) > 1:
                                selinux_data['process_context'] = lines[1].split()[0]
                    except:
                        pass
            
            if selinux_data['enabled']:
                self.logger.info("Collected SELinux context information")
        except Exception as e:
            self.add_error(f"Failed to collect SELinux context: {str(e)}")
        
        return selinux_data
    
    def collect_seccomp_profile(self) -> Dict[str, Any]:
        """Collect Seccomp profile information"""
        seccomp_data = {
            'mode': None,
            'profile': None,
            'custom_profile': None
        }
        
        try:
            if self.container_info:
                host_config = self.container_info[0].get('HostConfig', {})
                
                # Check SecurityOpt for seccomp settings
                security_opt = host_config.get('SecurityOpt', [])
                for opt in security_opt:
                    if 'seccomp' in opt:
                        seccomp_data['security_opt'] = opt
                        if 'unconfined' in opt:
                            seccomp_data['mode'] = 'unconfined'
                        else:
                            seccomp_data['mode'] = 'custom'
                
                # Check for custom seccomp profile
                seccomp_profile = host_config.get('SeccompProfile', '')
                if seccomp_profile:
                    seccomp_data['profile'] = seccomp_profile
            
            # Get seccomp status from /proc
            pid = self.get_container_pid()
            if pid:
                status_file = f"/proc/{pid}/status"
                if os.path.exists(status_file):
                    with open(status_file, 'r') as f:
                        for line in f:
                            if line.startswith('Seccomp:'):
                                seccomp_mode = line.split()[1]
                                seccomp_data['kernel_mode'] = seccomp_mode
                                break
            
            if seccomp_data.get('mode') or seccomp_data.get('kernel_mode'):
                self.logger.info("Collected Seccomp profile information")
        except Exception as e:
            self.add_error(f"Failed to collect Seccomp profile: {str(e)}")
        
        return seccomp_data
    
    def collect_capabilities(self) -> Dict[str, Any]:
        """Collect container capabilities"""
        capabilities_data = {
            'cap_add': [],
            'cap_drop': [],
            'effective': [],
            'permitted': [],
            'bounding': []
        }
        
        try:
            if self.container_info:
                host_config = self.container_info[0].get('HostConfig', {})
                
                # Get added/dropped capabilities
                capabilities_data['cap_add'] = host_config.get('CapAdd', []) or []
                capabilities_data['cap_drop'] = host_config.get('CapDrop', []) or []
            
            # Get actual capabilities from /proc
            pid = self.get_container_pid()
            if pid:
                status_file = f"/proc/{pid}/status"
                if os.path.exists(status_file):
                    with open(status_file, 'r') as f:
                        for line in f:
                            if line.startswith('CapEff:'):
                                capabilities_data['effective_hex'] = line.split()[1]
                            elif line.startswith('CapPrm:'):
                                capabilities_data['permitted_hex'] = line.split()[1]
                            elif line.startswith('CapBnd:'):
                                capabilities_data['bounding_hex'] = line.split()[1]
                
                # Try to decode capabilities using capsh if available
                try:
                    for cap_type in ['effective_hex', 'permitted_hex', 'bounding_hex']:
                        if cap_type in capabilities_data:
                            hex_value = capabilities_data[cap_type]
                            result = subprocess.run(['capsh', '--decode=' + hex_value], 
                                                  capture_output=True, text=True)
                            if result.returncode == 0:
                                cap_name = cap_type.replace('_hex', '')
                                capabilities_data[cap_name] = result.stdout.strip().split(',')
                except:
                    pass
            
            self.logger.info("Collected container capabilities")
        except Exception as e:
            self.add_error(f"Failed to collect capabilities: {str(e)}")
        
        return capabilities_data
    
    def collect_user_info(self) -> Dict[str, Any]:
        """Collect user and group information"""
        user_data = {
            'container_user': None,
            'uid': None,
            'gid': None,
            'groups': [],
            'passwd_file': None
        }
        
        try:
            if self.container_info:
                # Get user from config
                config = self.container_info[0].get('Config', {})
                user = config.get('User', '')
                if user:
                    user_data['container_user'] = user
                    
                    # Parse UID:GID if present
                    if ':' in user:
                        uid, gid = user.split(':', 1)
                        try:
                            user_data['uid'] = int(uid)
                            user_data['gid'] = int(gid)
                        except ValueError:
                            pass
                    else:
                        try:
                            user_data['uid'] = int(user)
                        except ValueError:
                            pass
            
            # Get actual process UID/GID
            pid = self.get_container_pid()
            if pid:
                status_file = f"/proc/{pid}/status"
                if os.path.exists(status_file):
                    with open(status_file, 'r') as f:
                        for line in f:
                            if line.startswith('Uid:'):
                                parts = line.split()
                                if len(parts) >= 5:
                                    user_data['real_uid'] = int(parts[1])
                                    user_data['effective_uid'] = int(parts[2])
                                    user_data['saved_uid'] = int(parts[3])
                                    user_data['fs_uid'] = int(parts[4])
                            elif line.startswith('Gid:'):
                                parts = line.split()
                                if len(parts) >= 5:
                                    user_data['real_gid'] = int(parts[1])
                                    user_data['effective_gid'] = int(parts[2])
                                    user_data['saved_gid'] = int(parts[3])
                                    user_data['fs_gid'] = int(parts[4])
                            elif line.startswith('Groups:'):
                                groups = line.split()[1:]
                                user_data['groups'] = [int(g) for g in groups]
            
            # Read passwd file from container
            merged_dir = self.get_merged_dir()
            if merged_dir:
                passwd_path = os.path.join(merged_dir, 'etc/passwd')
                if os.path.exists(passwd_path):
                    with open(passwd_path, 'r') as f:
                        user_data['passwd_file'] = f.read()
            
            self.logger.info("Collected user information")
        except Exception as e:
            self.add_error(f"Failed to collect user info: {str(e)}")
        
        return user_data
    
    def collect_security_opts(self) -> List[str]:
        """Collect all security options"""
        security_opts = []
        
        try:
            if self.container_info:
                host_config = self.container_info[0].get('HostConfig', {})
                security_opts = host_config.get('SecurityOpt', []) or []
                
                # Also collect other security-related settings
                privileged = host_config.get('Privileged', False)
                readonly_rootfs = host_config.get('ReadonlyRootfs', False)
                
                if privileged:
                    security_opts.append('privileged=true')
                if readonly_rootfs:
                    security_opts.append('readonly_rootfs=true')
            
            if security_opts:
                self.logger.info(f"Collected {len(security_opts)} security options")
        except Exception as e:
            self.add_error(f"Failed to collect security options: {str(e)}")
        
        return security_opts
    
    def get_merged_dir(self) -> Optional[str]:
        """Get merged directory path based on storage driver"""
        try:
            driver_data = self.get_graph_driver_data()
            storage_driver = self.get_storage_driver()
            
            if storage_driver in ['overlay', 'overlay2']:
                return driver_data.get('MergedDir')
            elif storage_driver == 'aufs':
                return driver_data.get('MergedDir') or f"/var/lib/docker/aufs/mnt/{self.container_id}"
        except:
            pass
        
        return None
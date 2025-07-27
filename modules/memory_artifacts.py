#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Memory Artifacts Collector Module

This module collects runtime memory artifacts from Docker containers, including
process information, environment variables, command lines, and memory mappings.

Classes:
    MemoryArtifactsCollector: Collects memory-related forensic artifacts

Author: Kim, Tae hoon (Francesco)
"""

import os
import subprocess
from typing import Dict, Any, List, Optional
from .base_collector import BaseCollector


class MemoryArtifactsCollector(BaseCollector):
    """
    Collector for runtime memory artifacts.
    
    This collector gathers memory-specific information including:
    - Process list with detailed information
    - Environment variables for all processes
    - Command line arguments
    - Open files and file descriptors
    - Memory mappings (/proc/PID/maps)
    - Process status information
    """
    
    def collect(self) -> Dict[str, Any]:
        """Collect memory artifacts"""
        self.logger.info(f"Collecting memory artifacts for container {self.container_id}")
        
        artifacts = {
            'container_id': self.container_id,
            'collection_time': self.get_current_time(),
            'process_list': self.collect_process_list(),
            'environment_variables': self.collect_environment_variables(),
            'command_lines': self.collect_command_lines(),
            'open_files': self.collect_open_files(),
            'memory_maps': self.collect_memory_maps(),
            'process_status': self.collect_process_status()
        }
        
        self.artifacts = artifacts
        return artifacts
    
    def get_current_time(self) -> str:
        """Get current time in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def collect_process_list(self) -> List[Dict[str, Any]]:
        """Collect detailed process information"""
        processes = []
        
        try:
            # Get process list using docker top
            cmd = ['docker', 'top', self.container_id, '-eo', 'pid,ppid,user,group,vsz,rss,comm,args']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    headers = lines[0].lower().split()
                    for line in lines[1:]:
                        parts = line.split(None, len(headers) - 1)
                        if len(parts) >= len(headers):
                            process = {}
                            for i, header in enumerate(headers):
                                process[header] = parts[i]
                            processes.append(process)
                
                self.logger.info(f"Collected {len(processes)} processes")
        except Exception as e:
            self.add_error(f"Failed to collect process list: {str(e)}")
        
        return processes
    
    def collect_environment_variables(self) -> Dict[str, Dict[str, str]]:
        """Collect environment variables for all processes"""
        env_vars = {}
        
        # Get container PID to access /proc
        container_pid = self.get_container_pid()
        if not container_pid:
            return env_vars
        
        try:
            # Get all PIDs in container
            pids = []
            
            # Method 1: From docker top
            cmd = ['docker', 'top', self.container_id, '-eo', 'pid']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    try:
                        pid = int(line.strip())
                        pids.append(pid)
                    except ValueError:
                        pass
            
            # Collect environment for each PID
            for pid in pids:
                env_file = f"/proc/{pid}/environ"
                if os.path.exists(env_file):
                    try:
                        with open(env_file, 'rb') as f:
                            env_data = f.read()
                        
                        # Parse null-separated environment variables
                        env_dict = {}
                        for env_var in env_data.split(b'\x00'):
                            if b'=' in env_var:
                                key, value = env_var.split(b'=', 1)
                                try:
                                    env_dict[key.decode('utf-8', errors='replace')] = value.decode('utf-8', errors='replace')
                                except:
                                    env_dict[str(key)] = str(value)
                        
                        if env_dict:
                            env_vars[str(pid)] = env_dict
                    except Exception as e:
                        self.logger.debug(f"Could not read environ for PID {pid}: {str(e)}")
            
            if env_vars:
                self.logger.info(f"Collected environment variables for {len(env_vars)} processes")
        except Exception as e:
            self.add_error(f"Failed to collect environment variables: {str(e)}")
        
        return env_vars
    
    def collect_command_lines(self) -> Dict[str, str]:
        """Collect command lines for all processes"""
        cmdlines = {}
        
        # Get container PID to access /proc
        container_pid = self.get_container_pid()
        if not container_pid:
            return cmdlines
        
        try:
            # Get all PIDs in container
            cmd = ['docker', 'top', self.container_id, '-eo', 'pid']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    try:
                        pid = int(line.strip())
                        cmdline_file = f"/proc/{pid}/cmdline"
                        
                        if os.path.exists(cmdline_file):
                            with open(cmdline_file, 'rb') as f:
                                cmdline_data = f.read()
                            
                            # Replace null bytes with spaces
                            cmdline = cmdline_data.replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
                            if cmdline:
                                cmdlines[str(pid)] = cmdline
                    except Exception as e:
                        self.logger.debug(f"Could not read cmdline for PID {line}: {str(e)}")
            
            if cmdlines:
                self.logger.info(f"Collected command lines for {len(cmdlines)} processes")
        except Exception as e:
            self.add_error(f"Failed to collect command lines: {str(e)}")
        
        return cmdlines
    
    def collect_open_files(self) -> List[Dict[str, Any]]:
        """Collect information about open files"""
        open_files = []
        
        pid = self.get_container_pid()
        if not pid:
            return open_files
        
        try:
            # Use nsenter with lsof to get open files
            cmd = ['nsenter', '-t', str(pid), '-p', '-m', 'lsof', '-p', str(pid)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) > 1:
                    # Parse lsof output
                    for line in lines[1:]:  # Skip header
                        parts = line.split(None, 8)
                        if len(parts) >= 9:
                            file_info = {
                                'command': parts[0],
                                'pid': parts[1],
                                'user': parts[2],
                                'fd': parts[3],
                                'type': parts[4],
                                'device': parts[5],
                                'size': parts[6],
                                'node': parts[7],
                                'name': parts[8]
                            }
                            open_files.append(file_info)
                
                if open_files:
                    self.logger.info(f"Collected {len(open_files)} open files")
            else:
                # Fallback: Try to read from /proc/PID/fd
                fd_dir = f"/proc/{pid}/fd"
                if os.path.exists(fd_dir):
                    for fd in os.listdir(fd_dir):
                        try:
                            fd_path = os.path.join(fd_dir, fd)
                            target = os.readlink(fd_path)
                            open_files.append({
                                'fd': fd,
                                'target': target,
                                'pid': str(pid)
                            })
                        except:
                            pass
        except Exception as e:
            self.add_error(f"Failed to collect open files: {str(e)}")
        
        return open_files
    
    def collect_memory_maps(self) -> Dict[str, List[Dict[str, Any]]]:
        """Collect memory mappings for processes"""
        memory_maps = {}
        
        # Get container PID
        container_pid = self.get_container_pid()
        if not container_pid:
            return memory_maps
        
        try:
            # Get main process memory map
            maps_file = f"/proc/{container_pid}/maps"
            if os.path.exists(maps_file):
                maps_data = []
                with open(maps_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 6:
                            map_entry = {
                                'address_range': parts[0],
                                'permissions': parts[1],
                                'offset': parts[2],
                                'device': parts[3],
                                'inode': parts[4],
                                'pathname': ' '.join(parts[5:]) if len(parts) > 5 else ''
                            }
                            
                            # Parse address range
                            if '-' in map_entry['address_range']:
                                start, end = map_entry['address_range'].split('-')
                                map_entry['start_address'] = start
                                map_entry['end_address'] = end
                                try:
                                    size = int(end, 16) - int(start, 16)
                                    map_entry['size_bytes'] = size
                                    map_entry['size_human'] = self._format_bytes(size)
                                except:
                                    pass
                            
                            maps_data.append(map_entry)
                
                if maps_data:
                    memory_maps[str(container_pid)] = maps_data
                    
                    # Summary statistics
                    total_size = sum(m.get('size_bytes', 0) for m in maps_data)
                    memory_maps['summary'] = {
                        'total_mappings': len(maps_data),
                        'total_size_bytes': total_size,
                        'total_size_human': self._format_bytes(total_size)
                    }
                    
                    self.logger.info(f"Collected {len(maps_data)} memory mappings")
        except Exception as e:
            self.add_error(f"Failed to collect memory maps: {str(e)}")
        
        return memory_maps
    
    def collect_process_status(self) -> Dict[str, Dict[str, Any]]:
        """Collect detailed process status information"""
        process_status = {}
        
        # Get container PID
        container_pid = self.get_container_pid()
        if not container_pid:
            return process_status
        
        try:
            # Collect status for main container process
            status_file = f"/proc/{container_pid}/status"
            if os.path.exists(status_file):
                status_data = {}
                with open(status_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            status_data[key.strip()] = value.strip()
                
                # Extract important fields
                process_status[str(container_pid)] = {
                    'name': status_data.get('Name'),
                    'state': status_data.get('State'),
                    'pid': status_data.get('Pid'),
                    'ppid': status_data.get('PPid'),
                    'threads': status_data.get('Threads'),
                    'vm_peak': status_data.get('VmPeak'),
                    'vm_size': status_data.get('VmSize'),
                    'vm_rss': status_data.get('VmRSS'),
                    'vm_data': status_data.get('VmData'),
                    'vm_stack': status_data.get('VmStk'),
                    'uid': status_data.get('Uid'),
                    'gid': status_data.get('Gid'),
                    'groups': status_data.get('Groups'),
                    'ns_pid': status_data.get('NSpid'),
                    'seccomp': status_data.get('Seccomp'),
                    'cpus_allowed': status_data.get('Cpus_allowed_list')
                }
                
                self.logger.info(f"Collected process status for PID {container_pid}")
        except Exception as e:
            self.add_error(f"Failed to collect process status: {str(e)}")
        
        return process_status
    
    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
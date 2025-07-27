#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Logging Artifacts Collector Module

This module collects logging and monitoring artifacts from Docker containers,
including container logs, Docker daemon logs, events, and cached logs.

Classes:
    LoggingArtifactsCollector: Collects logging-related forensic artifacts

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import subprocess
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from .base_collector import BaseCollector


class LoggingArtifactsCollector(BaseCollector):
    """
    Collector for logging and monitoring artifacts.
    
    This collector gathers logging-specific information including:
    - Container logs (JSON format and recent logs)
    - Docker daemon logs from journald
    - Docker events for the container
    - Cached container logs
    - Logging driver configuration
    """
    
    def collect(self) -> Dict[str, Any]:
        """Collect logging artifacts"""
        self.logger.info(f"Collecting logging artifacts for container {self.container_id}")
        
        artifacts = {
            'container_id': self.container_id,
            'collection_time': self.get_current_time(),
            'container_logs': self.collect_container_logs(),
            'journald_logs': self.collect_journald_logs(),
            'docker_events': self.collect_docker_events(),
            'cached_logs': self.collect_cached_logs(),
            'log_config': self.collect_log_configuration()
        }
        
        self.artifacts = artifacts
        return artifacts
    
    def get_current_time(self) -> str:
        """Get current time in ISO format"""
        return datetime.now().isoformat()
    
    def collect_container_logs(self) -> Dict[str, Any]:
        """Collect container logs from various sources"""
        logs_data = {
            'json_log_path': None,
            'json_log_size': 0,
            'recent_logs': None,
            'log_tail': []
        }
        
        try:
            # Get JSON log file path
            json_log_path = f"/var/lib/docker/containers/{self.container_id}/{self.container_id}-json.log"
            
            if os.path.exists(json_log_path):
                logs_data['json_log_path'] = json_log_path
                logs_data['json_log_size'] = os.path.getsize(json_log_path)
                
                # Get last 100 lines of logs
                try:
                    with open(json_log_path, 'r') as f:
                        # Read last 100 lines efficiently
                        lines = []
                        for line in f:
                            lines.append(line.strip())
                            if len(lines) > 100:
                                lines.pop(0)
                        
                        # Parse JSON log entries
                        for line in lines:
                            try:
                                log_entry = json.loads(line)
                                logs_data['log_tail'].append(log_entry)
                            except json.JSONDecodeError:
                                logs_data['log_tail'].append({'raw': line})
                    
                    self.logger.info(f"Collected {len(logs_data['log_tail'])} recent log entries")
                except Exception as e:
                    self.logger.warning(f"Could not parse JSON logs: {str(e)}")
            
            # Get logs using docker logs command
            try:
                cmd = ['docker', 'logs', '--tail', '50', '--timestamps', self.container_id]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    logs_data['recent_logs'] = result.stdout
                    if result.stderr:
                        logs_data['recent_logs_stderr'] = result.stderr
            except subprocess.TimeoutExpired:
                self.logger.warning("Docker logs command timed out")
            except Exception as e:
                self.logger.warning(f"Could not get docker logs: {str(e)}")
            
        except Exception as e:
            self.add_error(f"Failed to collect container logs: {str(e)}")
        
        return logs_data
    
    def collect_journald_logs(self) -> Dict[str, Any]:
        """Collect Docker daemon logs from journald"""
        journald_data = {
            'available': False,
            'docker_service_logs': [],
            'container_logs': []
        }
        
        # Check if we should collect journald logs
        if not self.config.get('ARTIFACTS', {}).get('LOG_JOURNALD_SERVICE', 'TRUE').upper() == 'TRUE':
            self.logger.info("Journald log collection disabled in config")
            return journald_data
        
        try:
            # Check if journalctl is available
            result = subprocess.run(['which', 'journalctl'], capture_output=True)
            if result.returncode != 0:
                self.logger.warning("journalctl not found")
                return journald_data
            
            journald_data['available'] = True
            
            # Get Docker service logs from last hour
            since_time = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            
            # Docker daemon logs
            cmd = [
                'journalctl', '-u', 'docker.service',
                '--since', since_time,
                '--no-pager',
                '-o', 'json'
            ]
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if line:
                            try:
                                log_entry = json.loads(line)
                                # Filter for container-related messages
                                if self.container_id[:12] in log_entry.get('MESSAGE', ''):
                                    journald_data['docker_service_logs'].append({
                                        'timestamp': log_entry.get('__REALTIME_TIMESTAMP'),
                                        'message': log_entry.get('MESSAGE'),
                                        'priority': log_entry.get('PRIORITY'),
                                        'unit': log_entry.get('_SYSTEMD_UNIT')
                                    })
                            except json.JSONDecodeError:
                                pass
                    
                    if journald_data['docker_service_logs']:
                        self.logger.info(f"Collected {len(journald_data['docker_service_logs'])} journald entries")
            except subprocess.TimeoutExpired:
                self.logger.warning("Journalctl command timed out")
            
            # Container-specific logs (if using journald logging driver)
            container_name = self.container_info[0].get('Name', '').lstrip('/')
            if container_name:
                cmd = [
                    'journalctl',
                    f'CONTAINER_NAME={container_name}',
                    '--since', since_time,
                    '--no-pager',
                    '-o', 'json'
                ]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and result.stdout:
                        lines = result.stdout.strip().split('\n')
                        for line in lines:
                            if line:
                                try:
                                    log_entry = json.loads(line)
                                    journald_data['container_logs'].append({
                                        'timestamp': log_entry.get('__REALTIME_TIMESTAMP'),
                                        'message': log_entry.get('MESSAGE'),
                                        'container_name': log_entry.get('CONTAINER_NAME'),
                                        'container_id': log_entry.get('CONTAINER_ID_FULL')
                                    })
                                except json.JSONDecodeError:
                                    pass
                except:
                    pass
            
        except Exception as e:
            self.add_error(f"Failed to collect journald logs: {str(e)}")
        
        return journald_data
    
    def collect_docker_events(self) -> List[Dict[str, Any]]:
        """Collect Docker events related to the container"""
        events = []
        
        try:
            # Get events from last hour
            since_time = (datetime.now() - timedelta(hours=1)).isoformat()
            
            cmd = [
                'docker', 'events',
                '--since', since_time,
                '--until', datetime.now().isoformat(),
                '--filter', f'container={self.container_id}',
                '--format', '{{json .}}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line:
                        try:
                            event = json.loads(line)
                            events.append(event)
                        except json.JSONDecodeError:
                            events.append({'raw': line})
                
                if events:
                    self.logger.info(f"Collected {len(events)} Docker events")
        except subprocess.TimeoutExpired:
            self.logger.warning("Docker events command timed out")
        except Exception as e:
            self.add_error(f"Failed to collect Docker events: {str(e)}")
        
        return events
    
    def collect_cached_logs(self) -> Dict[str, Any]:
        """Collect cached container logs"""
        cached_logs_data = {
            'cached_log_path': None,
            'cached_log_exists': False,
            'cached_log_content': None
        }
        
        try:
            cached_log_path = f"/var/lib/docker/containers/{self.container_id}/container-cached.log"
            cached_logs_data['cached_log_path'] = cached_log_path
            
            if os.path.exists(cached_log_path):
                cached_logs_data['cached_log_exists'] = True
                
                # Read cached log (usually small)
                try:
                    with open(cached_log_path, 'r') as f:
                        cached_logs_data['cached_log_content'] = f.read()
                    self.logger.info("Collected cached container log")
                except Exception as e:
                    self.logger.warning(f"Could not read cached log: {str(e)}")
        except Exception as e:
            self.add_error(f"Failed to collect cached logs: {str(e)}")
        
        return cached_logs_data
    
    def collect_log_configuration(self) -> Dict[str, Any]:
        """Collect container logging configuration"""
        log_config = {
            'driver': None,
            'driver_opts': {},
            'host_config': {}
        }
        
        try:
            if self.container_info:
                # Get log configuration from HostConfig
                host_config = self.container_info[0].get('HostConfig', {})
                log_config_data = host_config.get('LogConfig', {})
                
                log_config['driver'] = log_config_data.get('Type', 'json-file')
                log_config['driver_opts'] = log_config_data.get('Config', {})
                
                # Get container-specific config that affects logging
                config = self.container_info[0].get('Config', {})
                log_config['tty'] = config.get('Tty', False)
                log_config['attach_stdout'] = config.get('AttachStdout', True)
                log_config['attach_stderr'] = config.get('AttachStderr', True)
                
                self.logger.info(f"Container uses '{log_config['driver']}' logging driver")
        except Exception as e:
            self.add_error(f"Failed to collect log configuration: {str(e)}")
        
        return log_config
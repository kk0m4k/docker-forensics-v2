#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Plugin Artifacts Collector Module

This module collects plugin and extension-related artifacts from Docker,
including Docker plugins, volume/network/runtime plugins, Docker Compose
information, and third-party tools.

Classes:
    PluginArtifactsCollector: Collects plugin-related forensic artifacts

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import subprocess
import glob
import yaml
from typing import Dict, Any, List, Optional
from .base_collector import BaseCollector


class PluginArtifactsCollector(BaseCollector):
    """
    Collector for Docker plugins and extensions artifacts.
    
    This collector gathers plugin-specific information including:
    - Installed Docker plugins and their configurations
    - Volume driver plugins
    - Network driver plugins
    - Runtime plugins (runc, nvidia, kata, etc.)
    - Docker Compose project information
    - Docker Desktop extensions
    - Third-party Docker tools (docker-compose, podman, etc.)
    """
    
    def collect(self) -> Dict[str, Any]:
        """Collect plugin and extension artifacts"""
        self.logger.info(f"Collecting plugin artifacts for container {self.container_id}")
        
        artifacts = {
            'container_id': self.container_id,
            'collection_time': self.get_current_time(),
            'docker_plugins': self.collect_docker_plugins(),
            'volume_plugins': self.collect_volume_plugins(),
            'network_plugins': self.collect_network_plugins(),
            'runtime_plugins': self.collect_runtime_plugins(),
            'docker_compose': self.collect_docker_compose_info(),
            'docker_extensions': self.collect_docker_extensions(),
            'third_party_tools': self.collect_third_party_tools()
        }
        
        self.artifacts = artifacts
        return artifacts
    
    def get_current_time(self) -> str:
        """Get current time in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def collect_docker_plugins(self) -> Dict[str, Any]:
        """Collect information about installed Docker plugins"""
        plugins_data = {
            'installed_plugins': [],
            'plugin_directories': {},
            'plugin_configs': []
        }
        
        try:
            # List all plugins
            cmd = ['docker', 'plugin', 'ls', '--format', '{{json .}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line:
                        try:
                            plugin_info = json.loads(line)
                            plugins_data['installed_plugins'].append(plugin_info)
                            
                            # Get detailed plugin info
                            plugin_id = plugin_info.get('ID', '')
                            if plugin_id:
                                detail_cmd = ['docker', 'plugin', 'inspect', plugin_id]
                                detail_result = subprocess.run(detail_cmd, capture_output=True, text=True)
                                
                                if detail_result.returncode == 0:
                                    plugin_detail = json.loads(detail_result.stdout)
                                    if plugin_detail:
                                        plugins_data['plugin_configs'].append({
                                            'id': plugin_id,
                                            'name': plugin_info.get('Name'),
                                            'config': plugin_detail[0]
                                        })
                        except json.JSONDecodeError:
                            pass
            
            # Check plugin directories
            plugin_dir = "/var/lib/docker/plugins"
            if os.path.exists(plugin_dir):
                plugins_data['plugin_directories']['base_path'] = plugin_dir
                plugins_data['plugin_directories']['contents'] = []
                
                for item in os.listdir(plugin_dir):
                    item_path = os.path.join(plugin_dir, item)
                    item_info = {
                        'name': item,
                        'path': item_path,
                        'type': 'directory' if os.path.isdir(item_path) else 'file'
                    }
                    
                    # Check if it's related to our container
                    if os.path.isdir(item_path):
                        # Look for container references in plugin data
                        for root, dirs, files in os.walk(item_path):
                            for file in files:
                                if file.endswith('.json'):
                                    file_path = os.path.join(root, file)
                                    try:
                                        with open(file_path, 'r') as f:
                                            content = f.read()
                                        if self.container_id in content:
                                            item_info['container_related'] = True
                                            break
                                    except:
                                        pass
                    
                    plugins_data['plugin_directories']['contents'].append(item_info)
            
            if plugins_data['installed_plugins']:
                self.logger.info(f"Found {len(plugins_data['installed_plugins'])} Docker plugins")
        except Exception as e:
            self.add_error(f"Failed to collect Docker plugins: {str(e)}")
        
        return plugins_data
    
    def collect_volume_plugins(self) -> Dict[str, Any]:
        """Collect volume plugin information"""
        volume_plugins = {
            'drivers': [],
            'volumes_using_plugins': []
        }
        
        try:
            # Get volume driver information
            cmd = ['docker', 'info', '--format', '{{json .Plugins.Volume}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip() != 'null':
                try:
                    drivers = json.loads(result.stdout)
                    if isinstance(drivers, list):
                        volume_plugins['drivers'] = drivers
                except json.JSONDecodeError:
                    pass
            
            # Check if container uses any volume plugins
            if self.container_info:
                mounts = self.container_info[0].get('Mounts', [])
                for mount in mounts:
                    driver = mount.get('Driver', 'local')
                    if driver != 'local':
                        volume_info = {
                            'name': mount.get('Name'),
                            'driver': driver,
                            'destination': mount.get('Destination'),
                            'mode': mount.get('Mode'),
                            'rw': mount.get('RW')
                        }
                        volume_plugins['volumes_using_plugins'].append(volume_info)
            
            # Check for volume plugin socket files
            socket_paths = [
                "/run/docker/plugins",
                "/var/run/docker/plugins"
            ]
            
            for socket_path in socket_paths:
                if os.path.exists(socket_path):
                    socket_files = os.listdir(socket_path)
                    if socket_files:
                        volume_plugins['plugin_sockets'] = {
                            'path': socket_path,
                            'sockets': socket_files
                        }
            
            if volume_plugins['drivers'] or volume_plugins['volumes_using_plugins']:
                self.logger.info("Collected volume plugin information")
        except Exception as e:
            self.add_error(f"Failed to collect volume plugins: {str(e)}")
        
        return volume_plugins
    
    def collect_network_plugins(self) -> Dict[str, Any]:
        """Collect network plugin information"""
        network_plugins = {
            'drivers': [],
            'networks_using_plugins': [],
            'ipam_drivers': []
        }
        
        try:
            # Get network driver information
            cmd = ['docker', 'info', '--format', '{{json .Plugins.Network}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip() != 'null':
                try:
                    drivers = json.loads(result.stdout)
                    if isinstance(drivers, list):
                        network_plugins['drivers'] = drivers
                except json.JSONDecodeError:
                    pass
            
            # Get IPAM drivers
            cmd = ['docker', 'info', '--format', '{{json .Plugins.IPAM}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip() != 'null':
                try:
                    ipam_drivers = json.loads(result.stdout)
                    if isinstance(ipam_drivers, list):
                        network_plugins['ipam_drivers'] = ipam_drivers
                except json.JSONDecodeError:
                    pass
            
            # Check if container uses any network plugins
            if self.container_info:
                network_settings = self.container_info[0].get('NetworkSettings', {})
                networks = network_settings.get('Networks', {})
                
                for network_name, network_config in networks.items():
                    # Get network details
                    net_cmd = ['docker', 'network', 'inspect', network_name]
                    net_result = subprocess.run(net_cmd, capture_output=True, text=True)
                    
                    if net_result.returncode == 0:
                        try:
                            net_info = json.loads(net_result.stdout)
                            if net_info and net_info[0].get('Driver') not in ['bridge', 'host', 'none', 'overlay']:
                                network_plugins['networks_using_plugins'].append({
                                    'name': network_name,
                                    'driver': net_info[0].get('Driver'),
                                    'ipam_driver': net_info[0].get('IPAM', {}).get('Driver'),
                                    'container_config': network_config
                                })
                        except:
                            pass
            
            if network_plugins['drivers'] or network_plugins['networks_using_plugins']:
                self.logger.info("Collected network plugin information")
        except Exception as e:
            self.add_error(f"Failed to collect network plugins: {str(e)}")
        
        return network_plugins
    
    def collect_runtime_plugins(self) -> Dict[str, Any]:
        """Collect runtime/execution plugin information"""
        runtime_plugins = {
            'runtimes': {},
            'default_runtime': None,
            'container_runtime': None
        }
        
        try:
            # Get available runtimes
            cmd = ['docker', 'info', '--format', '{{json .Runtimes}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip() != 'null':
                try:
                    runtimes = json.loads(result.stdout)
                    if isinstance(runtimes, dict):
                        runtime_plugins['runtimes'] = runtimes
                except json.JSONDecodeError:
                    pass
            
            # Get default runtime
            cmd = ['docker', 'info', '--format', '{{.DefaultRuntime}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                runtime_plugins['default_runtime'] = result.stdout.strip()
            
            # Check container's runtime
            if self.container_info:
                host_config = self.container_info[0].get('HostConfig', {})
                container_runtime = host_config.get('Runtime')
                if container_runtime:
                    runtime_plugins['container_runtime'] = container_runtime
            
            # Check for runtime configuration files
            runtime_configs = [
                "/etc/docker/daemon.json",
                "/etc/containerd/config.toml",
                "/etc/nvidia-container-runtime/config.toml"
            ]
            
            for config_path in runtime_configs:
                if os.path.exists(config_path):
                    try:
                        with open(config_path, 'r') as f:
                            content = f.read()
                        
                        # Parse based on file type
                        if config_path.endswith('.json'):
                            config_data = json.loads(content)
                            if 'runtimes' in config_data:
                                runtime_plugins[f'config_{os.path.basename(config_path)}'] = config_data['runtimes']
                        elif config_path.endswith('.toml'):
                            # Basic TOML parsing for runtime info
                            if 'runtime' in content.lower():
                                runtime_plugins[f'config_{os.path.basename(config_path)}'] = 'Present (TOML)'
                    except:
                        pass
            
            if runtime_plugins['runtimes']:
                self.logger.info(f"Found {len(runtime_plugins['runtimes'])} runtime plugins")
        except Exception as e:
            self.add_error(f"Failed to collect runtime plugins: {str(e)}")
        
        return runtime_plugins
    
    def collect_docker_compose_info(self) -> Dict[str, Any]:
        """Collect Docker Compose related information"""
        compose_info = {
            'compose_files': [],
            'compose_projects': [],
            'environment_files': []
        }
        
        try:
            # Check if container has compose labels
            if self.container_info:
                labels = self.container_info[0].get('Config', {}).get('Labels', {})
                
                # Extract compose information from labels
                compose_data = {}
                for label, value in labels.items():
                    if label.startswith('com.docker.compose'):
                        compose_data[label] = value
                
                if compose_data:
                    compose_info['compose_labels'] = compose_data
                    
                    # Extract project info
                    project_name = compose_data.get('com.docker.compose.project')
                    if project_name:
                        compose_info['project_name'] = project_name
                        
                        # Try to find compose files
                        working_dir = compose_data.get('com.docker.compose.project.working_dir')
                        config_files = compose_data.get('com.docker.compose.project.config_files')
                        
                        if working_dir and config_files:
                            compose_info['working_directory'] = working_dir
                            compose_info['config_files'] = config_files.split(',')
                            
                            # Try to read compose files if accessible
                            for config_file in compose_info['config_files']:
                                file_path = os.path.join(working_dir, config_file) if not os.path.isabs(config_file) else config_file
                                if os.path.exists(file_path):
                                    try:
                                        with open(file_path, 'r') as f:
                                            content = yaml.safe_load(f)
                                        compose_info['compose_files'].append({
                                            'path': file_path,
                                            'content': content
                                        })
                                    except:
                                        compose_info['compose_files'].append({
                                            'path': file_path,
                                            'error': 'Could not read file'
                                        })
            
            # Look for .env files
            search_paths = ['/var/lib/docker/containers', '.']
            for search_path in search_paths:
                env_files = glob.glob(os.path.join(search_path, '**/.env'), recursive=True)
                for env_file in env_files:
                    if self.container_id[:12] in env_file:
                        compose_info['environment_files'].append(env_file)
            
            if compose_info.get('compose_labels'):
                self.logger.info("Container was created with Docker Compose")
        except Exception as e:
            self.add_error(f"Failed to collect Docker Compose info: {str(e)}")
        
        return compose_info
    
    def collect_docker_extensions(self) -> Dict[str, Any]:
        """Collect Docker Desktop extensions if applicable"""
        extensions_info = {
            'docker_desktop': False,
            'extensions': []
        }
        
        try:
            # Check if Docker Desktop is in use
            cmd = ['docker', 'info', '--format', '{{.OperatingSystem}}']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                os_info = result.stdout.strip()
                if 'Docker Desktop' in os_info:
                    extensions_info['docker_desktop'] = True
                    
                    # Try to list extensions (Docker Desktop specific)
                    ext_cmd = ['docker', 'extension', 'ls', '--format', '{{json .}}']
                    ext_result = subprocess.run(ext_cmd, capture_output=True, text=True)
                    
                    if ext_result.returncode == 0:
                        lines = ext_result.stdout.strip().split('\n')
                        for line in lines:
                            if line:
                                try:
                                    extension = json.loads(line)
                                    extensions_info['extensions'].append(extension)
                                except:
                                    pass
            
            # Check for extension directories
            extension_paths = [
                os.path.expanduser("~/.docker/desktop/extensions"),
                "/usr/local/lib/docker/extensions"
            ]
            
            for ext_path in extension_paths:
                if os.path.exists(ext_path):
                    extensions_info['extension_directories'] = extensions_info.get('extension_directories', [])
                    extensions_info['extension_directories'].append({
                        'path': ext_path,
                        'contents': os.listdir(ext_path)
                    })
            
            if extensions_info['docker_desktop']:
                self.logger.info("Collected Docker Desktop extensions information")
        except Exception as e:
            self.logger.debug(f"Could not collect Docker extensions (may not be Docker Desktop): {str(e)}")
        
        return extensions_info
    
    def collect_third_party_tools(self) -> Dict[str, Any]:
        """Collect information about third-party Docker tools"""
        tools_info = {
            'docker_cli_plugins': [],
            'credential_helpers': [],
            'other_tools': []
        }
        
        try:
            # Check for Docker CLI plugins
            cli_plugin_paths = [
                os.path.expanduser("~/.docker/cli-plugins"),
                "/usr/local/lib/docker/cli-plugins",
                "/usr/lib/docker/cli-plugins"
            ]
            
            for plugin_path in cli_plugin_paths:
                if os.path.exists(plugin_path):
                    for plugin in os.listdir(plugin_path):
                        plugin_file = os.path.join(plugin_path, plugin)
                        if os.path.isfile(plugin_file) and os.access(plugin_file, os.X_OK):
                            tools_info['docker_cli_plugins'].append({
                                'name': plugin,
                                'path': plugin_file,
                                'size': os.path.getsize(plugin_file)
                            })
            
            # Check for credential helpers
            docker_config = os.path.expanduser("~/.docker/config.json")
            if os.path.exists(docker_config):
                try:
                    with open(docker_config, 'r') as f:
                        config = json.load(f)
                    
                    cred_helpers = config.get('credHelpers', {})
                    if cred_helpers:
                        tools_info['credential_helpers'] = list(cred_helpers.items())
                    
                    # Check for credential store
                    cred_store = config.get('credsStore')
                    if cred_store:
                        tools_info['credential_store'] = cred_store
                except:
                    pass
            
            # Check for common third-party tools
            third_party_commands = [
                'docker-compose',
                'docker-machine',
                'podman',
                'crictl',
                'nerdctl'
            ]
            
            for tool in third_party_commands:
                result = subprocess.run(['which', tool], capture_output=True, text=True)
                if result.returncode == 0:
                    tool_path = result.stdout.strip()
                    # Get version
                    ver_result = subprocess.run([tool_path, '--version'], capture_output=True, text=True)
                    tools_info['other_tools'].append({
                        'name': tool,
                        'path': tool_path,
                        'version': ver_result.stdout.strip() if ver_result.returncode == 0 else 'Unknown'
                    })
            
            if tools_info['docker_cli_plugins'] or tools_info['other_tools']:
                self.logger.info("Collected third-party tools information")
        except Exception as e:
            self.add_error(f"Failed to collect third-party tools: {str(e)}")
        
        return tools_info
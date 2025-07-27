#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Artifacts Collector Module

This module collects network-related artifacts from Docker containers, including
network configuration, iptables rules, network connections, and DNS settings.

Classes:
    NetworkArtifactsCollector: Collects network-specific forensic artifacts

Author: Kim, Tae hoon (Francesco)
"""

import os
import json
import subprocess
import sqlite3
from typing import Dict, Any, List, Optional
from .base_collector import BaseCollector


class NetworkArtifactsCollector(BaseCollector):
    """
    Collector for network related artifacts.
    
    This collector gathers network-specific information including:
    - Docker network database (local-kv.db)
    - iptables/nftables rules
    - docker-proxy process information
    - Active network connections
    - Network namespaces and veth pairs
    - Network interfaces configuration
    - DNS configuration (resolv.conf, hosts)
    """
    
    def collect(self) -> Dict[str, Any]:
        """Collect network artifacts"""
        self.logger.info(f"Collecting network artifacts for container {self.container_id}")
        
        artifacts = {
            'container_id': self.container_id,
            'collection_time': self.get_current_time(),
            'network_db': self.collect_network_database(),
            'iptables_rules': self.collect_iptables_rules(),
            'nftables_rules': self.collect_nftables_rules(),
            'docker_proxy': self.collect_docker_proxy_info(),
            'network_connections': self.collect_network_connections(),
            'network_namespaces': self.collect_network_namespaces(),
            'network_interfaces': self.collect_network_interfaces(),
            'dns_config': self.collect_dns_config()
        }
        
        self.artifacts = artifacts
        return artifacts
    
    def get_current_time(self) -> str:
        """Get current time in ISO format"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def collect_network_database(self) -> Dict[str, Any]:
        """Collect Docker network metadata from local-kv.db"""
        network_db_data = {
            'path': None,
            'networks': [],
            'endpoints': [],
            'raw_data': {}
        }
        
        db_path = "/var/lib/docker/network/files/local-kv.db"
        
        try:
            if os.path.exists(db_path):
                network_db_data['path'] = db_path
                
                # Try to read the database
                try:
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    
                    # Get table names
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                    tables = cursor.fetchall()
                    
                    for table in tables:
                        table_name = table[0]
                        cursor.execute(f"SELECT * FROM {table_name}")
                        rows = cursor.fetchall()
                        
                        # Get column names
                        cursor.execute(f"PRAGMA table_info({table_name})")
                        columns = [col[1] for col in cursor.fetchall()]
                        
                        # Convert to dict
                        table_data = []
                        for row in rows:
                            row_dict = dict(zip(columns, row))
                            # Look for container-specific data
                            if 'key' in row_dict and 'value' in row_dict:
                                if self.container_id in str(row_dict.get('key', '')):
                                    table_data.append(row_dict)
                        
                        if table_data:
                            network_db_data['raw_data'][table_name] = table_data
                    
                    conn.close()
                    self.logger.info(f"Collected network database from {db_path}")
                except Exception as e:
                    self.logger.warning(f"Could not parse network database: {str(e)}")
                    # Fall back to reading raw file
                    with open(db_path, 'rb') as f:
                        network_db_data['raw_binary_size'] = os.path.getsize(db_path)
        except Exception as e:
            self.add_error(f"Failed to collect network database: {str(e)}")
        
        return network_db_data
    
    def collect_iptables_rules(self) -> Dict[str, Any]:
        """Collect iptables rules related to Docker"""
        iptables_data = {
            'docker_chains': [],
            'nat_rules': [],
            'filter_rules': []
        }
        
        try:
            # Check if iptables is available
            result = subprocess.run(['which', 'iptables'], capture_output=True)
            if result.returncode != 0:
                self.logger.warning("iptables not found")
                return iptables_data
            
            # Get Docker-related chains
            tables = ['nat', 'filter']
            for table in tables:
                try:
                    # List chains
                    cmd = ['iptables', '-t', table, '-L', '-n', '-v', '--line-numbers']
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        current_chain = None
                        docker_rules = []
                        
                        for line in lines:
                            if line.startswith('Chain'):
                                chain_name = line.split()[1]
                                if 'DOCKER' in chain_name:
                                    current_chain = chain_name
                                    iptables_data['docker_chains'].append(chain_name)
                            elif current_chain and line.strip() and not line.startswith('num'):
                                # Parse rule if it contains container ID or docker interface
                                if self.container_id[:12] in line or 'docker0' in line or 'br-' in line:
                                    docker_rules.append({
                                        'chain': current_chain,
                                        'table': table,
                                        'rule': line.strip()
                                    })
                        
                        if docker_rules:
                            if table == 'nat':
                                iptables_data['nat_rules'] = docker_rules
                            else:
                                iptables_data['filter_rules'] = docker_rules
                except Exception as e:
                    self.logger.warning(f"Failed to get iptables {table} rules: {str(e)}")
            
            if iptables_data['docker_chains']:
                self.logger.info(f"Collected {len(iptables_data['docker_chains'])} Docker iptables chains")
        except Exception as e:
            self.add_error(f"Failed to collect iptables rules: {str(e)}")
        
        return iptables_data
    
    def collect_nftables_rules(self) -> Dict[str, Any]:
        """Collect nftables rules if in use"""
        nftables_data = {
            'enabled': False,
            'docker_tables': [],
            'rules': []
        }
        
        try:
            # Check if nftables is available
            result = subprocess.run(['which', 'nft'], capture_output=True)
            if result.returncode != 0:
                return nftables_data
            
            # List ruleset
            result = subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, text=True)
            if result.returncode == 0:
                nftables_data['enabled'] = True
                
                # Parse output for Docker-related rules
                lines = result.stdout.split('\n')
                in_docker_table = False
                current_table = None
                
                for line in lines:
                    if 'table' in line and 'docker' in line.lower():
                        in_docker_table = True
                        current_table = line.strip()
                        nftables_data['docker_tables'].append(current_table)
                    elif 'table' in line:
                        in_docker_table = False
                    elif in_docker_table and line.strip():
                        if self.container_id[:12] in line:
                            nftables_data['rules'].append({
                                'table': current_table,
                                'rule': line.strip()
                            })
                
                if nftables_data['docker_tables']:
                    self.logger.info(f"Collected {len(nftables_data['docker_tables'])} Docker nftables tables")
        except Exception as e:
            self.logger.debug(f"nftables not available or failed: {str(e)}")
        
        return nftables_data
    
    def collect_docker_proxy_info(self) -> List[Dict[str, Any]]:
        """Collect information about docker-proxy processes"""
        docker_proxy_info = []
        
        try:
            # Find docker-proxy processes
            cmd = ['ps', 'aux']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'docker-proxy' in line and self.container_id[:12] in line:
                        parts = line.split()
                        if len(parts) >= 11:
                            # Parse docker-proxy command line
                            proxy_info = {
                                'pid': parts[1],
                                'cpu': parts[2],
                                'mem': parts[3],
                                'command': ' '.join(parts[10:])
                            }
                            
                            # Extract port mapping from command
                            cmd_parts = proxy_info['command'].split()
                            for i, part in enumerate(cmd_parts):
                                if part == '-container-ip' and i + 1 < len(cmd_parts):
                                    proxy_info['container_ip'] = cmd_parts[i + 1]
                                elif part == '-container-port' and i + 1 < len(cmd_parts):
                                    proxy_info['container_port'] = cmd_parts[i + 1]
                                elif part == '-host-ip' and i + 1 < len(cmd_parts):
                                    proxy_info['host_ip'] = cmd_parts[i + 1]
                                elif part == '-host-port' and i + 1 < len(cmd_parts):
                                    proxy_info['host_port'] = cmd_parts[i + 1]
                            
                            docker_proxy_info.append(proxy_info)
                
                if docker_proxy_info:
                    self.logger.info(f"Found {len(docker_proxy_info)} docker-proxy processes")
        except Exception as e:
            self.add_error(f"Failed to collect docker-proxy info: {str(e)}")
        
        return docker_proxy_info
    
    def collect_network_connections(self) -> Dict[str, Any]:
        """Collect network connections using nsenter"""
        connections_data = {
            'listening_ports': [],
            'established_connections': [],
            'all_connections': []
        }
        
        pid = self.get_container_pid()
        if not pid:
            self.add_error("Cannot collect network connections without container PID")
            return connections_data
        
        try:
            # Use nsenter to enter container network namespace
            cmd = ['nsenter', '-t', str(pid), '-n', 'ss', '-tulpn']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 5:
                            connection = {
                                'proto': parts[0],
                                'state': parts[1],
                                'local_address': parts[4],
                                'peer_address': parts[5] if len(parts) > 5 else ''
                            }
                            
                            if 'LISTEN' in connection['state']:
                                connections_data['listening_ports'].append(connection)
                            elif 'ESTAB' in connection['state']:
                                connections_data['established_connections'].append(connection)
                            
                            connections_data['all_connections'].append(connection)
            
            # Also try with lsof for more detailed info
            cmd = ['nsenter', '-t', str(pid), '-n', 'lsof', '-i', '-n', '-P']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                connections_data['lsof_output'] = result.stdout
                self.logger.info("Collected network connections using lsof")
            
            if connections_data['all_connections']:
                self.logger.info(f"Collected {len(connections_data['all_connections'])} network connections")
        except Exception as e:
            self.add_error(f"Failed to collect network connections: {str(e)}")
        
        return connections_data
    
    def collect_network_namespaces(self) -> Dict[str, Any]:
        """Collect network namespace information"""
        namespace_data = {
            'namespace_id': None,
            'namespace_path': None,
            'veth_pairs': []
        }
        
        pid = self.get_container_pid()
        if not pid:
            return namespace_data
        
        try:
            # Get network namespace ID
            netns_path = f"/proc/{pid}/ns/net"
            if os.path.exists(netns_path):
                namespace_data['namespace_path'] = netns_path
                stat = os.stat(netns_path)
                namespace_data['namespace_id'] = stat.st_ino
            
            # Find veth pairs
            cmd = ['ip', 'link', 'show', 'type', 'veth']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for i in range(0, len(lines), 2):
                    if i + 1 < len(lines):
                        line = lines[i]
                        if '@' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                veth_name = parts[1].strip().split('@')[0]
                                # Check if this veth is related to our container
                                cmd = ['nsenter', '-t', str(pid), '-n', 'ip', 'link', 'show']
                                ns_result = subprocess.run(cmd, capture_output=True, text=True)
                                if ns_result.returncode == 0 and veth_name in ns_result.stdout:
                                    namespace_data['veth_pairs'].append({
                                        'host_interface': veth_name,
                                        'details': line
                                    })
            
            if namespace_data['namespace_id']:
                self.logger.info(f"Collected network namespace info: {namespace_data['namespace_id']}")
        except Exception as e:
            self.add_error(f"Failed to collect network namespace info: {str(e)}")
        
        return namespace_data
    
    def collect_network_interfaces(self) -> List[Dict[str, Any]]:
        """Collect network interface information from container namespace"""
        interfaces = []
        
        pid = self.get_container_pid()
        if not pid:
            return interfaces
        
        try:
            # Get interfaces in container namespace
            cmd = ['nsenter', '-t', str(pid), '-n', 'ip', '-j', 'addr', 'show']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    ifaces = json.loads(result.stdout)
                    for iface in ifaces:
                        interface_info = {
                            'name': iface.get('ifname'),
                            'index': iface.get('ifindex'),
                            'mtu': iface.get('mtu'),
                            'state': iface.get('operstate'),
                            'mac': iface.get('address'),
                            'addresses': []
                        }
                        
                        # Extract IP addresses
                        for addr_info in iface.get('addr_info', []):
                            interface_info['addresses'].append({
                                'family': addr_info.get('family'),
                                'address': addr_info.get('local'),
                                'prefix': addr_info.get('prefixlen'),
                                'scope': addr_info.get('scope')
                            })
                        
                        interfaces.append(interface_info)
                except json.JSONDecodeError:
                    # Fall back to text parsing
                    cmd = ['nsenter', '-t', str(pid), '-n', 'ip', 'addr', 'show']
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode == 0:
                        interfaces.append({'raw_output': result.stdout})
            
            if interfaces:
                self.logger.info(f"Collected {len(interfaces)} network interfaces")
        except Exception as e:
            self.add_error(f"Failed to collect network interfaces: {str(e)}")
        
        return interfaces
    
    def collect_dns_config(self) -> Dict[str, Any]:
        """Collect DNS configuration"""
        dns_data = {
            'resolv_conf': None,
            'resolv_conf_hash': None,
            'hosts': None,
            'hostname': None
        }
        
        try:
            container_path = f"/var/lib/docker/containers/{self.container_id}"
            
            # Read resolv.conf
            resolv_path = os.path.join(container_path, "resolv.conf")
            if os.path.exists(resolv_path):
                with open(resolv_path, 'r') as f:
                    dns_data['resolv_conf'] = f.read()
            
            # Read resolv.conf.hash
            resolv_hash_path = os.path.join(container_path, "resolv.conf.hash")
            if os.path.exists(resolv_hash_path):
                with open(resolv_hash_path, 'r') as f:
                    dns_data['resolv_conf_hash'] = f.read().strip()
            
            # Read hosts file (already collected in security artifacts, but DNS related)
            hosts_path = os.path.join(container_path, "hosts")
            if os.path.exists(hosts_path):
                with open(hosts_path, 'r') as f:
                    dns_data['hosts'] = f.read()
            
            # Read hostname
            hostname_path = os.path.join(container_path, "hostname")
            if os.path.exists(hostname_path):
                with open(hostname_path, 'r') as f:
                    dns_data['hostname'] = f.read().strip()
            
            self.logger.info("Collected DNS configuration")
        except Exception as e:
            self.add_error(f"Failed to collect DNS config: {str(e)}")
        
        return dns_data
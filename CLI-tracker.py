#!/usr/bin/env python3
"""
Network Device Tracer - Trace devices through networks using ARP/MAC tables

This program traces a path through a network by querying ARP and MAC address tables 
on Cisco and Fortinet devices. Starting from a Layer 3 boundary (router/firewall), 
it discovers the complete path to the target device.

Features:
- Supports both password and key-based SSH authentication
- Handles different Cisco OS variants (IOS, IOS-XE, NX-OS) automatically
- Supports Fortinet firewalls
- Creates text-based diagram of the device path
- Includes robust error handling for SSH connection issues
- Saves discovered paths to text files
- Processes devices sequentially

Author: Network Engineer
Date: May 2025
"""

import os
import sys
import re
import time
import socket
import logging
import argparse
import getpass
from typing import Dict, List, Tuple, Optional, Any, Union
from datetime import datetime
from functools import wraps

# Third-party libraries
import paramiko
from netmiko import ConnectHandler, SSHDetect
# Fixed import statement to use the correct module path in newer Netmiko versions
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_tracer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Constants for device types
CISCO_IOS = 'cisco_ios'
CISCO_XE = 'cisco_xe'
CISCO_NXOS = 'cisco_nxos'
FORTINET = 'fortinet'

# Helper functions for improved error handling
def retry(max_retries=3, initial_delay=1, backoff_factor=2):
    """Retry decorator with exponential backoff."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            delay = initial_delay
            
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except (NetmikoTimeoutException, SSHException) as e:
                    retries += 1
                    if retries == max_retries:
                        raise
                    
                    logger.warning(f"Attempt {retries} failed: {str(e)}. Retrying in {delay} seconds...")
                    time.sleep(delay)
                    delay *= backoff_factor
            
            return func(*args, **kwargs)  # Final attempt
        return wrapper
    return decorator


class NetworkDevice:
    """
    Class representing a network device with connection management and command execution
    """
    def __init__(
        self, 
        hostname: str, 
        username: str, 
        password: str = None, 
        key_file: str = None, 
        port: int = 22,
        device_type: str = None
    ):
        """
        Initialize the NetworkDevice with connection parameters.
        
        Args:
            hostname: IP address or hostname of the device
            username: Username for authentication
            password: Password for password-based authentication (optional)
            key_file: Path to SSH private key for key-based authentication (optional)
            port: SSH port number (default: 22)
            device_type: Device type if known (if None, will be auto-detected)
        """
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.device_type = device_type
        self.connection = None
        self.detected_device_type = None
        self.full_name = None
        
        # Validate that at least one authentication method is provided
        if not password and not key_file:
            raise ValueError("Either password or key_file must be provided")
    
    @retry(max_retries=3, initial_delay=2, backoff_factor=2)
    def connect(self, max_retries: int = 3, retry_interval: int = 5) -> bool:
        """
        Establish connection to the device with retry mechanism.
        
        Args:
            max_retries: Maximum number of connection attempts
            retry_interval: Seconds to wait between retries
            
        Returns:
            bool: True if connection established successfully, False otherwise
        """
        # Connection parameters for Netmiko
        device_params = {
            'host': self.hostname,
            'username': self.username,
            'port': self.port,
            'conn_timeout': 20,        # Connection timeout in seconds
            'read_timeout': 60,        # Read timeout for operations
            'session_timeout': 60,     # Session timeout
        }
        
        # Set authentication method
        if self.key_file:
            device_params['use_keys'] = True
            device_params['key_file'] = self.key_file
        else:
            device_params['password'] = self.password
        
        # If device_type is not specified, attempt to auto-detect
        if not self.device_type:
            try:
                logger.info(f"Attempting to detect device type for {self.hostname}...")
                device_params['device_type'] = 'autodetect'
                
                # Create SSHDetect object for auto-detection
                guesser = SSHDetect(**device_params)
                best_match = guesser.autodetect()
                
                if best_match:
                    self.detected_device_type = best_match
                    logger.info(f"Detected device type: {best_match}")
                else:
                    # If detection fails, try common device types
                    logger.warning(f"Could not auto-detect device type. Trying common types...")
                    common_types = [CISCO_IOS, CISCO_XE, CISCO_NXOS, FORTINET]
                    
                    for device_type in common_types:
                        try:
                            logger.info(f"Trying {device_type}...")
                            device_params['device_type'] = device_type
                            connection = ConnectHandler(**device_params)
                            # If connection succeeds, we've found the right type
                            connection.disconnect()
                            self.detected_device_type = device_type
                            logger.info(f"Successfully connected as {device_type}")
                            break
                        except Exception as e:
                            logger.debug(f"Failed with {device_type}: {str(e)}")
                            continue
                    
                    if not self.detected_device_type:
                        logger.error("Failed to detect device type or connect with common types")
                        return False
            
            except Exception as e:
                logger.error(f"Error during device type detection: {str(e)}")
                return False
        else:
            # Use the provided device type
            self.detected_device_type = self.device_type
        
        # Now connect with the detected or provided device type
        device_params['device_type'] = self.detected_device_type
        
        # Attempt connection with retry mechanism
        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Connection attempt {attempt} to {self.hostname}...")
                self.connection = ConnectHandler(**device_params)
                
                # Handle Fortinet login banner if present
                if self.detected_device_type == FORTINET:
                    # Check if there's a login banner requiring acknowledgment
                    output = self.connection.read_channel()
                    if "(Press 'a' to accept)" in output:
                        self.connection.write_channel('a\n')
                        logger.info("Accepted Fortinet login banner")
                
                # Get device prompt as a basic connection test
                prompt = self.connection.find_prompt()
                logger.info(f"Connected successfully to {self.hostname}. Prompt: {prompt}")
                
                # Get device information for the path diagram
                self.full_name = self._get_device_name()
                
                return True
                
            except NetmikoTimeoutException:
                logger.error(f"Connection to {self.hostname} timed out")
                if attempt < max_retries:
                    logger.info(f"Retrying in {retry_interval} seconds...")
                    time.sleep(retry_interval)
                
            except NetmikoAuthenticationException:
                logger.error(f"Authentication failed for {self.hostname}")
                return False
                
            except SSHException as e:
                logger.error(f"SSH error: {str(e)}")
                if attempt < max_retries:
                    logger.info(f"Retrying in {retry_interval} seconds...")
                    time.sleep(retry_interval)
                
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                if attempt < max_retries:
                    logger.info(f"Retrying in {retry_interval} seconds...")
                    time.sleep(retry_interval)
        
        logger.error(f"Failed to connect to {self.hostname} after {max_retries} attempts")
        return False
    
    def disconnect(self) -> None:
        """Safely disconnect from the device"""
        if self.connection:
            self.connection.disconnect()
            logger.info(f"Disconnected from {self.hostname}")
            self.connection = None
    
    def execute_command(self, command: str) -> str:
        """
        Execute a command on the device and return the output.
        
        Args:
            command: Command to execute
            
        Returns:
            str: Command output
        
        Raises:
            ConnectionError: If not connected to the device
        """
        if not self.connection:
            raise ConnectionError(f"Not connected to {self.hostname}")
        
        try:
            # Handle Fortinet VDOM if applicable
            if self.detected_device_type == FORTINET:
                # Check if we need to enter a global context for commands
                if command.startswith("get system") or command.startswith("diagnose"):
                    # Check if we're in a VDOM context
                    prompt = self.connection.find_prompt()
                    if "VDOM" in prompt and not "(global)" in prompt:
                        # Switch to global context
                        self.connection.send_command("config global", expect_string=r"#")
                        output = self.connection.send_command(command)
                        # Return to previous context
                        self.connection.send_command("end", expect_string=r"#")
                        return output
            
            # For Cisco devices, ensure we're in enable mode for privileged commands
            if self.detected_device_type.startswith('cisco'):
                if not self.connection.check_enable_mode():
                    self.connection.enable()
            
            # Execute the command
            output = self.connection.send_command(command)
            return output
        
        except Exception as e:
            logger.error(f"Error executing command '{command}': {str(e)}")
            raise
    
    def _get_device_name(self) -> str:
        """
        Get the hostname of the device for better identification in the path diagram.
        
        Returns:
            str: Device hostname or IP if hostname cannot be determined
        """
        try:
            if self.detected_device_type.startswith('cisco'):
                output = self.execute_command("show run | include hostname")
                match = re.search(r'hostname (.+)', output)
                if match:
                    return match.group(1)
            
            elif self.detected_device_type == FORTINET:
                output = self.execute_command("get system status")
                match = re.search(r'Hostname: (.+)', output)
                if match:
                    return match.group(1)
            
            # If we couldn't get the hostname, return the IP
            return self.hostname
            
        except Exception:
            # If there's any error, just return the IP address
            return self.hostname


class DeviceTracer:
    """
    Main class for tracing a device through the network.
    """
    def __init__(self, log_level: int = logging.INFO):
        """
        Initialize the device tracer.
        
        Args:
            log_level: Logging level (default: INFO)
        """
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        
        # Store the discovered path
        self.path = []
    
    def get_mac_from_ip(self, device: NetworkDevice, ip_address: str) -> Optional[str]:
        """
        Query the ARP table to find the MAC address for an IP address.
        
        Args:
            device: The NetworkDevice object
            ip_address: Target IP address
            
        Returns:
            str: MAC address if found, None otherwise
        """
        try:
            # Different commands for different device types
            if device.detected_device_type.startswith('cisco'):
                # For Cisco devices
                output = device.execute_command(f"show ip arp | include {ip_address}")
                
                # Parse the output
                match = re.search(r'Internet\s+{}\s+\S+\s+(\S+)'.format(re.escape(ip_address)), output)
                if match:
                    return match.group(1).lower()  # Convert MAC to lowercase for consistency
            
            elif device.detected_device_type == FORTINET:
                # For Fortinet devices
                output = device.execute_command("get system arp")
                
                # Parse the output
                for line in output.splitlines():
                    if ip_address in line:
                        match = re.search(r'{}\s+\S+\s+(\S+)'.format(re.escape(ip_address)), line)
                        if match:
                            return match.group(1).lower()
            
            self.logger.warning(f"MAC address for IP {ip_address} not found in ARP table")
            return None
            
        except Exception as e:
            self.logger.error(f"Error querying ARP table: {str(e)}")
            return None
    
    def get_port_from_mac(self, device: NetworkDevice, mac_address: str) -> Optional[Dict[str, str]]:
        """
        Query the MAC address table to find which port a MAC address was learned on.
        
        Args:
            device: The NetworkDevice object
            mac_address: The MAC address to look for
            
        Returns:
            Dict with port and vlan information if found, None otherwise
        """
        try:
            # Different commands for different device types
            if device.detected_device_type.startswith('cisco'):
                # For Cisco IOS and IOS-XE devices
                if device.detected_device_type in [CISCO_IOS, CISCO_XE]:
                    output = device.execute_command(f"show mac address-table address {mac_address}")
                    
                    # Parse the output - the format is different across Cisco OS variants
                    for line in output.splitlines():
                        # Match the pattern: vlan, mac, type, ports
                        match = re.search(r'(\d+)\s+' + re.escape(mac_address) + r'\s+\S+\s+(\S+)', line, re.IGNORECASE)
                        if match:
                            return {
                                'vlan': match.group(1),
                                'port': match.group(2),
                                'type': 'access'  # Assume access port initially
                            }
                
                # For Cisco NX-OS devices
                elif device.detected_device_type == CISCO_NXOS:
                    output = device.execute_command(f"show mac address-table address {mac_address}")
                    
                    for line in output.splitlines():
                        # Match the pattern: vlan, mac, type, age, port
                        match = re.search(r'(\d+)\s+' + re.escape(mac_address) + r'\s+\S+\s+\S+\s+(\S+)', line, re.IGNORECASE)
                        if match:
                            return {
                                'vlan': match.group(1),
                                'port': match.group(2),
                                'type': 'access'  # Assume access port initially
                            }
            
            elif device.detected_device_type == FORTINET:
                # For Fortinet devices - the command is different
                # First try hardware switch MAC table
                output = device.execute_command("diagnose netlink brctl name host root.b")
                
                for line in output.splitlines():
                    # Look for the MAC address in the line
                    if mac_address in line.lower():
                        # Parse Fortinet MAC table format
                        parts = line.split()
                        if len(parts) >= 3:
                            # The port/interface name is in the 3rd column
                            return {
                                'vlan': 'N/A',  # Fortinet doesn't show VLAN in this output
                                'port': parts[2],
                                'type': 'access'
                            }
                
                # If not found in hardware switch, try searching for MAC in all interfaces
                output = device.execute_command("diagnose netlink macview")
                for line in output.splitlines():
                    if mac_address in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            return {
                                'vlan': 'N/A',
                                'port': parts[0],  # Interface name is usually the first field
                                'type': 'access'
                            }
            
            self.logger.warning(f"Port for MAC {mac_address} not found in MAC address table")
            return None
            
        except Exception as e:
            self.logger.error(f"Error querying MAC address table: {str(e)}")
            return None
    
    def check_if_trunk_port(self, device: NetworkDevice, port: str) -> bool:
        """
        Check if a port is configured as a trunk port.
        
        Args:
            device: The NetworkDevice object
            port: Port name to check
            
        Returns:
            bool: True if trunk port, False otherwise
        """
        try:
            if device.detected_device_type.startswith('cisco'):
                output = device.execute_command(f"show interface {port} switchport")
                
                # Check if the port is a trunk port
                if "Administrative Mode: trunk" in output or "Operational Mode: trunk" in output:
                    return True
            
            # Fortinet doesn't have the concept of trunk ports in the same way
            # We'll assume it's not a trunk port
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking if port {port} is a trunk: {str(e)}")
            return False
    
    def get_neighbor_from_port(self, device: NetworkDevice, port: str) -> Optional[Dict[str, str]]:
        """
        Use CDP/LLDP to find the neighbor device connected to a port.
        
        Args:
            device: The NetworkDevice object
            port: Port name to check for neighbors
            
        Returns:
            Dict with neighbor information if found, None otherwise
        """
        try:
            neighbor_info = None
            
            # Try CDP first for Cisco devices
            if device.detected_device_type.startswith('cisco'):
                # Try CDP first
                output = device.execute_command(f"show cdp neighbors {port} detail")
                
                # Check if we got valid CDP information
                if "Device ID:" in output:
                    # Extract the neighbor IP address
                    ip_match = re.search(r'IP(?:v4)?\s+address:\s+(\d+\.\d+\.\d+\.\d+)', output)
                    if ip_match:
                        neighbor_ip = ip_match.group(1)
                        
                        # Extract the remote port
                        port_match = re.search(r'Interface:\s+\S+,\s+Port ID \(outgoing port\):\s+(\S+)', output)
                        remote_port = port_match.group(1) if port_match else "Unknown"
                        
                        # Extract the platform information
                        platform_match = re.search(r'Platform:\s+([^,]+)', output)
                        platform = platform_match.group(1).strip() if platform_match else "Unknown"
                        
                        # Extract the device ID/hostname
                        device_match = re.search(r'Device ID:\s+(.+?)(?:\r|\n)', output)
                        device_id = device_match.group(1).strip() if device_match else neighbor_ip
                        
                        neighbor_info = {
                            'ip_address': neighbor_ip,
                            'port': remote_port,
                            'platform': platform,
                            'device_id': device_id,
                            'protocol': 'CDP'
                        }
                
                # If CDP doesn't return any neighbor, try LLDP
                if not neighbor_info:
                    output = device.execute_command(f"show lldp neighbors {port} detail")
                    
                    # Check if we got valid LLDP information
                    if "System Name:" in output or "Port ID:" in output:
                        # Extract the neighbor IP address
                        ip_match = re.search(r'Management Address:\s+(\d+\.\d+\.\d+\.\d+)', output)
                        if ip_match:
                            neighbor_ip = ip_match.group(1)
                            
                            # Extract the remote port
                            port_match = re.search(r'Port ID:\s+(.+?)(?:\r|\n)', output)
                            remote_port = port_match.group(1).strip() if port_match else "Unknown"
                            
                            # Extract the system description
                            desc_match = re.search(r'System Description:\s+(.+?)(?:\r|\n|\*\*\*)', output, re.DOTALL)
                            platform = desc_match.group(1).strip() if desc_match else "Unknown"
                            
                            # Extract the system name
                            name_match = re.search(r'System Name:\s+(.+?)(?:\r|\n)', output)
                            device_id = name_match.group(1).strip() if name_match else neighbor_ip
                            
                            neighbor_info = {
                                'ip_address': neighbor_ip,
                                'port': remote_port,
                                'platform': platform,
                                'device_id': device_id,
                                'protocol': 'LLDP'
                            }
            
            # For Fortinet, try LLDP
            elif device.detected_device_type == FORTINET:
                output = device.execute_command(f"diagnose lldp neighbor-summary {port}")
                
                # Parse Fortinet LLDP output
                if "neighbor-summary" in output and not "No neighbors on" in output:
                    # Detailed info for Fortinet LLDP
                    detail_output = device.execute_command(f"get system interface {port}")
                    
                    # Extract IP from interface details
                    ip_match = re.search(r'ip\s+(\d+\.\d+\.\d+\.\d+)', detail_output)
                    neighbor_ip = ip_match.group(1) if ip_match else "Unknown"
                    
                    # Basic info from summary
                    parts = output.splitlines()
                    for line in parts:
                        if port in line:
                            fields = line.split()
                            if len(fields) >= 3:
                                neighbor_info = {
                                    'ip_address': neighbor_ip,
                                    'port': fields[2] if len(fields) > 2 else "Unknown",
                                    'platform': "Fortinet",
                                    'device_id': fields[1] if len(fields) > 1 else neighbor_ip,
                                    'protocol': 'LLDP'
                                }
            
            return neighbor_info
            
        except Exception as e:
            self.logger.error(f"Error getting neighbor for port {port}: {str(e)}")
            return None
    
    def trace_device(self, start_device: NetworkDevice, target_ip: str, 
                     max_hops: int = 10, credentials: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Trace a device through the network starting from a Layer 3 device.
        
        Args:
            start_device: The starting network device (Layer 3 boundary)
            target_ip: IP address of the target device
            max_hops: Maximum number of hops to traverse
            credentials: Dict containing 'username', 'password', and optional 'key_file'
            
        Returns:
            List of dicts representing the path to the target device
        """
        self.path = []
        current_device = start_device
        
        # Step 1: Find the MAC address from the IP in the ARP table
        mac_address = self.get_mac_from_ip(current_device, target_ip)
        if not mac_address:
            self.logger.error(f"Could not find MAC address for IP {target_ip}")
            return self.path
        
        self.logger.info(f"Found MAC address {mac_address} for IP {target_ip}")
        
        # Initialize the hop counter
        hop_count = 0
        
        while hop_count < max_hops:
            # Add the current device to the path
            self.path.append({
                'hop': hop_count + 1,
                'device_name': current_device.full_name or current_device.hostname,
                'device_ip': current_device.hostname,
                'device_type': current_device.detected_device_type
            })
            
            # Step 2: Find the port where the MAC was learned
            port_info = self.get_port_from_mac(current_device, mac_address)
            if not port_info:
                self.logger.warning(f"Could not find port for MAC {mac_address} on {current_device.hostname}")
                break
            
            # Update the current path entry with port information
            self.path[-1]['exit_port'] = port_info['port']
            self.path[-1]['vlan'] = port_info['vlan']
            
            # Check if this is a trunk port
            is_trunk = self.check_if_trunk_port(current_device, port_info['port'])
            self.path[-1]['port_type'] = 'trunk' if is_trunk else 'access'
            
            # Step 3: Check if there's a neighbor on this port
            neighbor = self.get_neighbor_from_port(current_device, port_info['port'])
            
            # If no neighbor found, we've reached the end device
            if not neighbor:
                self.logger.info(f"No neighbor found on port {port_info['port']} - end of path")
                break
            
            # Update the current path entry with neighbor information
            self.path[-1]['neighbor'] = neighbor['device_id']
            self.path[-1]['neighbor_ip'] = neighbor['ip_address']
            self.path[-1]['neighbor_port'] = neighbor['port']
            
            # Step 4: Connect to the neighbor device and continue tracing
            self.logger.info(f"Connecting to next hop: {neighbor['ip_address']}")
            
            # Disconnect from current device before moving to next
            current_device.disconnect()
            
            # Connect to the neighbor device
            next_device = NetworkDevice(
                hostname=neighbor['ip_address'],
                username=credentials['username'],
                password=credentials.get('password'),
                key_file=credentials.get('key_file')
            )
            
            if not next_device.connect():
                self.logger.error(f"Failed to connect to {neighbor['ip_address']}")
                break
            
            # Move to the next device
            current_device = next_device
            hop_count += 1
        
        # Disconnect from the last device
        if current_device and current_device.connection:
            current_device.disconnect()
        
        return self.path
    
    def create_path_diagram(self) -> str:
        """
        Create a text-based diagram of the discovered path.
        
        Returns:
            str: Text diagram representing the path
        """
        if not self.path:
            return "No path discovered"
        
        # Use Unicode box drawing characters for a better looking diagram
        h_line = "─"
        v_line = "│"
        top_left = "┌"
        top_right = "┐"
        bottom_left = "└"
        bottom_right = "┘"
        
        diagram = "\n" + "═" * 70 + "\n"
        diagram += "NETWORK PATH DIAGRAM\n"
        diagram += "═" * 70 + "\n\n"
        
        # Create the device boxes and connections
        for i, hop in enumerate(self.path):
            # Device box
            device_type = hop['device_type'].replace('cisco_', '').upper()
            
            diagram += f"{top_left}{h_line * 29}{top_right}\n"
            diagram += f"{v_line} {hop['device_name']:<27} {v_line}\n"
            diagram += f"{v_line} Type: {device_type:<22} {v_line}\n"
            diagram += f"{v_line} IP: {hop['device_ip']:<24} {v_line}\n"
            diagram += f"{bottom_left}{h_line * 29}{bottom_right}\n"
            
            # Show outgoing port if available
            if 'exit_port' in hop:
                diagram += f"{top_left}{h_line * 29}{top_right}\n"
                diagram += f"{v_line} Port: {hop['exit_port']:<22} {v_line}\n"
                if 'port_type' in hop:
                    diagram += f"{v_line} Type: {hop['port_type']:<22} {v_line}\n"
                if 'vlan' in hop and hop['vlan'] != 'N/A':
                    diagram += f"{v_line} VLAN: {hop['vlan']:<22} {v_line}\n"
                diagram += f"{bottom_left}{h_line * 29}{bottom_right}\n"
            
            # Show connection to next device if available
            if i < len(self.path) - 1 and 'neighbor' in hop:
                diagram += f"          {v_line}  \n"
                diagram += f"          {v_line}  \n"
                diagram += f"{top_left}{h_line * 29}{top_right}\n"
                diagram += f"{v_line} {hop['neighbor']:<27} {v_line}\n"
                diagram += f"{v_line} Port: {hop['neighbor_port']:<22} {v_line}\n"
                diagram += f"{bottom_left}{h_line * 29}{bottom_right}\n"
                diagram += f"          {v_line}  \n"
                diagram += f"          {v_line}  \n"
        
        # Add the target device at the end if not already in the path
        if self.path and 'neighbor' in self.path[-1]:
            diagram += f"{top_left}{h_line * 29}{top_right}\n"
            diagram += f"{v_line} {self.path[-1]['neighbor']:<27} {v_line}\n"
            diagram += f"{v_line} (Target Device)                {v_line}\n"
            diagram += f"{bottom_left}{h_line * 29}{bottom_right}\n"
        
        return diagram
    
    def generate_detailed_path_diagram(self) -> str:
        """
        Generate a more detailed Unicode-based path diagram.
        
        Returns:
            str: Enhanced text diagram with better formatting and more details
        """
        if not self.path:
            return "No path discovered"
        
        result = [f"Device Path Trace Results:"]
        result.append("=" * 70)
        
        for i, hop in enumerate(self.path):
            # Device information
            result.append(f"Hop {i+1}: {hop['device_name']} ({hop['device_ip']})")
            result.append(f"  └── Type: {hop['device_type']}")
            
            # Port information
            if 'exit_port' in hop:
                result.append(f"  └── Exit Port: {hop['exit_port']}")
                if 'port_type' in hop:
                    result.append(f"      └── Type: {hop['port_type']}")
                if 'vlan' in hop and hop['vlan'] != 'N/A':
                    result.append(f"      └── VLAN: {hop['vlan']}")
            
            # Neighbor information
            if 'neighbor' in hop:
                result.append(f"  └── Connected to: {hop['neighbor']}")
                result.append(f"      └── IP: {hop['neighbor_ip']}")
                result.append(f"      └── Port: {hop['neighbor_port']}")
            
            if i < len(self.path) - 1:
                result.append("  │")
                result.append("  ↓")
        
        # Add the target device if applicable
        if self.path and 'neighbor' in self.path[-1]:
            result.append(f"Target Device: {self.path[-1]['neighbor']} ({target_ip})")
        
        return "\n".join(result)
    
    def save_path_to_file(self, target_ip: str, filename: str = None) -> str:
        """
        Save the discovered path to a text file.
        
        Args:
            target_ip: IP address of the target device
            filename: Optional filename, auto-generated if None
            
        Returns:
            str: Path to the saved file
        """
        if not self.path:
            self.logger.warning("No path to save")
            return None
        
        # Create a default filename if none provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"path_to_{target_ip.replace('.', '_')}_{timestamp}.txt"
        
        # Ensure the path exists
        output_dir = "path_traces"
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        
        # Create the content
        content = f"Path Trace to {target_ip}\n"
        content += f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        content += f"Number of hops: {len(self.path)}\n\n"
        
        # Add detailed hop information
        for i, hop in enumerate(self.path):
            content += f"Hop {i+1}: {hop['device_name']} ({hop['device_ip']})\n"
            
            for key, value in hop.items():
                if key not in ['hop', 'device_name', 'device_ip']:
                    content += f"  {key}: {value}\n"
            
            content += "\n"
        
        # Add the diagram
        content += self.create_path_diagram()
        
        # Add enhanced diagram
        content += "\n\n" + "=" * 70 + "\n"
        content += "DETAILED PATH VIEW\n" 
        content += "=" * 70 + "\n"
        content += self.generate_detailed_path_diagram()
        
        # Write to file
        try:
            with open(filepath, 'w') as f:
                f.write(content)
            
            self.logger.info(f"Path saved to {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Error saving path to file: {str(e)}")
            return None


def parse_arguments():
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Network Device Tracer - Trace devices through networks using ARP/MAC tables",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument("start_device", help="IP address of the starting Layer 3 device")
    parser.add_argument("target_device", help="IP address of the target device to trace")
    parser.add_argument("-u", "--username", required=True, help="Username for device authentication")
    parser.add_argument("-p", "--password", help="Password for device authentication (if omitted, will prompt)")
    parser.add_argument("-k", "--key-file", help="Path to SSH private key file for authentication")
    parser.add_argument("-m", "--max-hops", type=int, default=10, help="Maximum number of hops to traverse")
    parser.add_argument("-o", "--output", help="Output file name (default: auto-generated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    return parser.parse_args()


def main():
    """Main function to run the device tracer"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get password if not provided
    password = args.password
    if not password and not args.key_file:
        password = getpass.getpass("Enter password: ")
    
    try:
        # Connect to the starting device
        logger.info(f"Connecting to starting device: {args.start_device}")
        start_device = NetworkDevice(
            hostname=args.start_device,
            username=args.username,
            password=password,
            key_file=args.key_file
        )
        
        if not start_device.connect():
            logger.error(f"Failed to connect to starting device: {args.start_device}")
            return 1
        
        # Create device tracer
        tracer = DeviceTracer(log_level=logging.DEBUG if args.verbose else logging.INFO)
        
        # Credentials for subsequent devices
        credentials = {
            'username': args.username,
            'password': password,
            'key_file': args.key_file
        }
        
        # Trace the device
        logger.info(f"Starting trace to target device: {args.target_device}")
        path = tracer.trace_device(
            start_device=start_device,
            target_ip=args.target_device,
            max_hops=args.max_hops,
            credentials=credentials
        )
        
        if not path:
            logger.error("No path found to the target device")
            return 1
        
        # Create and display the path diagram
        diagram = tracer.create_path_diagram()
        print(diagram)
        
        # Save the path to a file
        filepath = tracer.save_path_to_file(
            target_ip=args.target_device,
            filename=args.output
        )
        
        if filepath:
            logger.info(f"Path trace saved to: {filepath}")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Operation interrupted by user")
        return 1
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
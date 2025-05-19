#!/usr/bin/env python3
"""
Network Device Tracer GUI - Graphical interface for tracing devices through networks

This program provides a user-friendly GUI for tracing paths through a network by querying 
ARP and MAC address tables on Cisco and Fortinet devices.

Features:
- Easy-to-use graphical interface
- Support for both password and key-based SSH authentication
- Option to display just the end port or the full path
- Graphical visualization of network paths
- Progress tracking during operations
- Save and load trace results
- Cross-platform support (Windows 10/11 and Linux)

Author: Network Engineer
Date: May 2025
"""

import os
import sys
import re
import time
import socket
import logging
import json
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter.font import Font
import getpass
from typing import Dict, List, Tuple, Optional, Any, Union
from datetime import datetime
from functools import wraps
from pathlib import Path

# Third-party libraries
try:
    import paramiko
    from netmiko import ConnectHandler, SSHDetect
    # Fixed import statement to use the correct module path in newer Netmiko versions
    from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
    from paramiko.ssh_exception import SSHException
except ImportError:
    messagebox.showerror("Missing Dependencies", 
                         "Required libraries are missing. Please install them using:\n\n"
                         "pip install paramiko netmiko")
    sys.exit(1)

# Set up logging
log_directory = "logs"
os.makedirs(log_directory, exist_ok=True)
log_file = os.path.join(log_directory, f"network_tracer_{datetime.now().strftime('%Y%m%d')}.log")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Constants for device types
CISCO_IOS = 'cisco_ios'
CISCO_XE = 'cisco_xe'
CISCO_NXOS = 'cisco_nxos'
FORTINET = 'fortinet'

# Colors for GUI
DARK_BG = "#2E3B4E"
LIGHT_BG = "#F0F0F0"
ACCENT_COLOR = "#3498DB"
SUCCESS_COLOR = "#2ECC71"
WARNING_COLOR = "#F39C12"
ERROR_COLOR = "#E74C3C"
TEXT_COLOR = "#ECF0F1"
BORDER_COLOR = "#7F8C8D"

# Helper decorator for retry logic
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
        device_type: str = None,
        progress_callback=None
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
            progress_callback: Function to call for progress updates
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
        self.progress_callback = progress_callback
        
        # Validate that at least one authentication method is provided
        if not password and not key_file:
            raise ValueError("Either password or key_file must be provided")
    
    def update_progress(self, message, percentage=None):
        """Update progress if callback is provided"""
        if self.progress_callback:
            self.progress_callback(message, percentage)
        logger.info(message)
    
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
                self.update_progress(f"Detecting device type for {self.hostname}...", 10)
                device_params['device_type'] = 'autodetect'
                
                # Create SSHDetect object for auto-detection
                guesser = SSHDetect(**device_params)
                best_match = guesser.autodetect()
                
                if best_match:
                    self.detected_device_type = best_match
                    self.update_progress(f"Detected device type: {best_match}", 20)
                else:
                    # If detection fails, try common device types
                    self.update_progress(f"Auto-detection failed. Trying common device types...", 15)
                    common_types = [CISCO_IOS, CISCO_XE, CISCO_NXOS, FORTINET]
                    
                    for device_type in common_types:
                        try:
                            self.update_progress(f"Trying {device_type}...", 15)
                            device_params['device_type'] = device_type
                            connection = ConnectHandler(**device_params)
                            # If connection succeeds, we've found the right type
                            connection.disconnect()
                            self.detected_device_type = device_type
                            self.update_progress(f"Successfully connected as {device_type}", 20)
                            break
                        except Exception as e:
                            logger.debug(f"Failed with {device_type}: {str(e)}")
                            continue
                    
                    if not self.detected_device_type:
                        self.update_progress(f"Failed to detect device type for {self.hostname}", 0)
                        return False
            
            except Exception as e:
                self.update_progress(f"Error during device detection: {str(e)}", 0)
                return False
        else:
            # Use the provided device type
            self.detected_device_type = self.device_type
        
        # Now connect with the detected or provided device type
        device_params['device_type'] = self.detected_device_type
        
        # Attempt connection with retry mechanism
        for attempt in range(1, max_retries + 1):
            try:
                self.update_progress(f"Connection attempt {attempt} to {self.hostname}...", 25)
                self.connection = ConnectHandler(**device_params)
                
                # Handle Fortinet login banner if present
                if self.detected_device_type == FORTINET:
                    # Check if there's a login banner requiring acknowledgment
                    output = self.connection.read_channel()
                    if "(Press 'a' to accept)" in output:
                        self.connection.write_channel('a\n')
                        self.update_progress("Accepted Fortinet login banner", 30)
                
                # Get device prompt as a basic connection test
                prompt = self.connection.find_prompt()
                self.update_progress(f"Connected to {self.hostname}. Prompt: {prompt}", 35)
                
                # Get device information for the path diagram
                self.full_name = self._get_device_name()
                
                return True
                
            except NetmikoTimeoutException:
                self.update_progress(f"Connection to {self.hostname} timed out", 0)
                if attempt < max_retries:
                    self.update_progress(f"Retrying in {retry_interval} seconds...", 0)
                    time.sleep(retry_interval)
                
            except NetmikoAuthenticationException:
                self.update_progress(f"Authentication failed for {self.hostname}", 0)
                return False
                
            except SSHException as e:
                self.update_progress(f"SSH error: {str(e)}", 0)
                if attempt < max_retries:
                    self.update_progress(f"Retrying in {retry_interval} seconds...", 0)
                    time.sleep(retry_interval)
                
            except Exception as e:
                self.update_progress(f"Unexpected error: {str(e)}", 0)
                if attempt < max_retries:
                    self.update_progress(f"Retrying in {retry_interval} seconds...", 0)
                    time.sleep(retry_interval)
        
        self.update_progress(f"Failed to connect to {self.hostname} after {max_retries} attempts", 0)
        return False
    
    def disconnect(self) -> None:
        """Safely disconnect from the device"""
        if self.connection:
            self.connection.disconnect()
            self.update_progress(f"Disconnected from {self.hostname}", None)
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
            self.update_progress(f"Executing: {command}", None)
            output = self.connection.send_command(command)
            return output
        
        except Exception as e:
            self.update_progress(f"Error executing command '{command}': {str(e)}", None)
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
    def __init__(self, log_level: int = logging.INFO, progress_callback=None):
        """
        Initialize the device tracer.
        
        Args:
            log_level: Logging level (default: INFO)
            progress_callback: Function to call for progress updates
        """
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        self.progress_callback = progress_callback
        
        # Store the discovered path
        self.path = []
        self.end_device_port = None
        self.target_ip = None
    
    def update_progress(self, message, percentage=None):
        """Update progress if callback is provided"""
        if self.progress_callback:
            self.progress_callback(message, percentage)
        self.logger.info(message)
    
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
                    mac = match.group(1).lower()  # Convert MAC to lowercase for consistency
                    self.update_progress(f"Found MAC address {mac} for IP {ip_address}", 40)
                    return mac
            
            elif device.detected_device_type == FORTINET:
                # For Fortinet devices
                output = device.execute_command("get system arp")
                
                # Parse the output
                for line in output.splitlines():
                    if ip_address in line:
                        match = re.search(r'{}\s+\S+\s+(\S+)'.format(re.escape(ip_address)), line)
                        if match:
                            mac = match.group(1).lower()
                            self.update_progress(f"Found MAC address {mac} for IP {ip_address}", 40)
                            return mac
            
            self.update_progress(f"MAC address for IP {ip_address} not found in ARP table", 0)
            return None
            
        except Exception as e:
            self.update_progress(f"Error querying ARP table: {str(e)}", 0)
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
                            port_info = {
                                'vlan': match.group(1),
                                'port': match.group(2),
                                'type': 'access'  # Assume access port initially
                            }
                            self.update_progress(f"Found MAC {mac_address} on port {port_info['port']}", 45)
                            return port_info
                
                # For Cisco NX-OS devices
                elif device.detected_device_type == CISCO_NXOS:
                    output = device.execute_command(f"show mac address-table address {mac_address}")
                    
                    for line in output.splitlines():
                        # Match the pattern: vlan, mac, type, age, port
                        match = re.search(r'(\d+)\s+' + re.escape(mac_address) + r'\s+\S+\s+\S+\s+(\S+)', line, re.IGNORECASE)
                        if match:
                            port_info = {
                                'vlan': match.group(1),
                                'port': match.group(2),
                                'type': 'access'  # Assume access port initially
                            }
                            self.update_progress(f"Found MAC {mac_address} on port {port_info['port']}", 45)
                            return port_info
            
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
                            port_info = {
                                'vlan': 'N/A',  # Fortinet doesn't show VLAN in this output
                                'port': parts[2],
                                'type': 'access'
                            }
                            self.update_progress(f"Found MAC {mac_address} on port {port_info['port']}", 45)
                            return port_info
                
                # If not found in hardware switch, try searching for MAC in all interfaces
                output = device.execute_command("diagnose netlink macview")
                for line in output.splitlines():
                    if mac_address in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            port_info = {
                                'vlan': 'N/A',
                                'port': parts[0],  # Interface name is usually the first field
                                'type': 'access'
                            }
                            self.update_progress(f"Found MAC {mac_address} on port {port_info['port']}", 45)
                            return port_info
            
            self.update_progress(f"Port for MAC {mac_address} not found in MAC address table", 0)
            return None
            
        except Exception as e:
            self.update_progress(f"Error querying MAC address table: {str(e)}", 0)
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
                    self.update_progress(f"Port {port} is a trunk port", None)
                    return True
            
            # Fortinet doesn't have the concept of trunk ports in the same way
            # We'll assume it's not a trunk port
            
            return False
            
        except Exception as e:
            self.update_progress(f"Error checking if port {port} is a trunk: {str(e)}", None)
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
                        self.update_progress(f"Found CDP neighbor: {device_id}", 50)
                
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
                            self.update_progress(f"Found LLDP neighbor: {device_id}", 50)
            
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
                                self.update_progress(f"Found LLDP neighbor: {neighbor_info['device_id']}", 50)
            
            return neighbor_info
            
        except Exception as e:
            self.update_progress(f"Error getting neighbor for port {port}: {str(e)}", None)
            return None
    
    def trace_device(self, start_device: NetworkDevice, target_ip: str, 
                     max_hops: int = 10, credentials: Dict[str, str] = None,
                     end_port_only: bool = False) -> List[Dict[str, Any]]:
        """
        Trace a device through the network starting from a Layer 3 device.
        
        Args:
            start_device: The starting network device (Layer 3 boundary)
            target_ip: IP address of the target device
            max_hops: Maximum number of hops to traverse
            credentials: Dict containing 'username', 'password', and optional 'key_file'
            end_port_only: If True, stop after finding the port and don't trace further
            
        Returns:
            List of dicts representing the path to the target device
        """
        self.path = []
        self.target_ip = target_ip
        current_device = start_device
        
        # Step 1: Find the MAC address from the IP in the ARP table
        self.update_progress("Looking up MAC address...", 35)
        mac_address = self.get_mac_from_ip(current_device, target_ip)
        if not mac_address:
            self.update_progress(f"Could not find MAC address for IP {target_ip}", 0)
            return self.path
        
        self.update_progress(f"Found MAC address {mac_address} for IP {target_ip}", 40)
        
        # Initialize the hop counter
        hop_count = 0
        
        while hop_count < max_hops:
            # Calculate and update progress percentage
            progress = 40 + min(50, (hop_count / max_hops) * 50)
            self.update_progress(f"Tracing hop {hop_count + 1}...", progress)
            
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
                self.update_progress(f"Could not find port for MAC {mac_address} on {current_device.hostname}", 0)
                break
            
            # Update the current path entry with port information
            self.path[-1]['exit_port'] = port_info['port']
            self.path[-1]['vlan'] = port_info['vlan']
            
            # Check if this is a trunk port
            is_trunk = self.check_if_trunk_port(current_device, port_info['port'])
            self.path[-1]['port_type'] = 'trunk' if is_trunk else 'access'
            
            # Store the end device port information
            if hop_count == 0 or len(self.path) == 1:
                self.end_device_port = {
                    'device_name': current_device.full_name or current_device.hostname,
                    'device_ip': current_device.hostname,
                    'port': port_info['port'],
                    'vlan': port_info['vlan'],
                    'port_type': 'trunk' if is_trunk else 'access'
                }
                
                # If user only wants the end port, we're done
                if end_port_only:
                    self.update_progress(f"Found end port: {port_info['port']} on {current_device.hostname}", 100)
                    break
            
            # Step 3: Check if there's a neighbor on this port
            neighbor = self.get_neighbor_from_port(current_device, port_info['port'])
            
            # If no neighbor found, we've reached the end device
            if not neighbor:
                self.update_progress(f"No neighbor found on port {port_info['port']} - end of path", 100)
                break
            
            # Update the current path entry with neighbor information
            self.path[-1]['neighbor'] = neighbor['device_id']
            self.path[-1]['neighbor_ip'] = neighbor['ip_address']
            self.path[-1]['neighbor_port'] = neighbor['port']
            
            # Step 4: Connect to the neighbor device and continue tracing
            self.update_progress(f"Connecting to next hop: {neighbor['ip_address']}", 50 + min(40, (hop_count / max_hops) * 40))
            
            # Disconnect from current device before moving to next
            current_device.disconnect()
            
            # Connect to the neighbor device
            next_device = NetworkDevice(
                hostname=neighbor['ip_address'],
                username=credentials['username'],
                password=credentials.get('password'),
                key_file=credentials.get('key_file'),
                progress_callback=self.progress_callback
            )
            
            if not next_device.connect():
                self.update_progress(f"Failed to connect to {neighbor['ip_address']}", 0)
                break
            
            # Move to the next device
            current_device = next_device
            hop_count += 1
        
        # Disconnect from the last device
        if current_device and current_device.connection:
            current_device.disconnect()
        
        self.update_progress("Trace completed", 100)
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
        
        result = [f"Device Path Trace Results for {self.target_ip}:"]
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
            result.append(f"Target Device: {self.path[-1]['neighbor']} ({self.target_ip})")
        
        return "\n".join(result)
    
    def get_json_data(self) -> dict:
        """
        Get a JSON-serializable representation of the trace results.
        
        Returns:
            dict: JSON-serializable representation of trace results
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'target_ip': self.target_ip,
            'path': self.path,
            'end_device_port': self.end_device_port
        }
    
    def load_from_json(self, data: dict) -> None:
        """
        Load trace results from JSON data.
        
        Args:
            data: JSON data to load
        """
        self.target_ip = data.get('target_ip')
        self.path = data.get('path', [])
        self.end_device_port = data.get('end_device_port')
    
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
            self.update_progress("No path to save", 0)
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
            
            self.update_progress(f"Path saved to {filepath}", 100)
            return filepath
            
        except Exception as e:
            self.update_progress(f"Error saving path to file: {str(e)}", 0)
            return None
    
    def save_json_to_file(self, filename: str = None) -> str:
        """
        Save the discovered path to a JSON file.
        
        Args:
            filename: Optional filename, auto-generated if None
            
        Returns:
            str: Path to the saved file
        """
        if not self.path and not self.end_device_port:
            self.update_progress("No path to save", 0)
            return None
        
        # Create a default filename if none provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"path_to_{self.target_ip.replace('.', '_')}_{timestamp}.json"
        
        # Ensure the path exists
        output_dir = "path_traces"
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        
        # Get JSON data
        json_data = self.get_json_data()
        
        # Write to file
        try:
            with open(filepath, 'w') as f:
                json.dump(json_data, f, indent=2)
            
            self.update_progress(f"Path saved to {filepath}", 100)
            return filepath
            
        except Exception as e:
            self.update_progress(f"Error saving path to file: {str(e)}", 0)
            return None
    
    @staticmethod
    def load_json_from_file(filepath: str) -> dict:
        """
        Load trace results from a JSON file.
        
        Args:
            filepath: Path to the JSON file
            
        Returns:
            dict: Loaded JSON data
        """
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading JSON file: {str(e)}")
            return {}


class NetworkCanvas(tk.Canvas):
    """Canvas for displaying network path visualization"""
    
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.parent = parent
        self.node_radius = 20
        self.node_spacing_x = 150
        self.node_spacing_y = 100
        self.font = Font(family='Arial', size=9)
        self.items = {}
        self.layer_counts = {}
        
    def clear(self):
        """Clear the canvas"""
        self.delete("all")
        self.items = {}
        self.layer_counts = {}
    
    def draw_path(self, path, target_ip):
        """Draw the network path on the canvas"""
        self.clear()
        
        if not path:
            self.create_text(self.winfo_width() // 2, self.winfo_height() // 2, 
                            text="No path to display", fill="black", font=('Arial', 12))
            return
        
        # Calculate the positions
        # Layer 0: Core devices
        # Layer 1: Distribution devices
        # Layer 2: Access devices
        # Layer 3: End devices
        
        # Count devices in each layer for positioning
        for i, hop in enumerate(path):
            layer = min(i, 2)  # Max 3 layers (0, 1, 2) for networking devices
            self.layer_counts[layer] = self.layer_counts.get(layer, 0) + 1
        
        # Add target device to the end if it has a neighbor
        if path and 'neighbor' in path[-1]:
            self.layer_counts[3] = self.layer_counts.get(3, 0) + 1

        # Calculate canvas size
        max_layer_count = max(self.layer_counts.values()) if self.layer_counts else 1
        canvas_width = max(self.winfo_width(), (max_layer_count + 1) * self.node_spacing_x)
        canvas_height = max(self.winfo_height(), (len(self.layer_counts) + 1) * self.node_spacing_y)
        
        self.config(width=canvas_width, height=canvas_height)
        
        # Draw the devices and connections
        current_layer_counts = {}
        
        for i, hop in enumerate(path):
            layer = min(i, 2)  # Max 3 layers for networking devices
            
            # Calculate position
            current_layer_counts[layer] = current_layer_counts.get(layer, 0) + 1
            position_in_layer = current_layer_counts[layer]
            total_in_layer = self.layer_counts[layer]
            
            # Center the nodes in each layer
            x = (canvas_width / (total_in_layer + 1)) * position_in_layer
            y = (layer + 1) * self.node_spacing_y
            
            # Draw the device
            device_type = hop['device_type'].replace('cisco_', '').upper()
            device_name = hop['device_name']
            port = hop.get('exit_port', 'N/A')
            
            # Create the node
            node_id = f"node_{i}"
            color = self._get_node_color(device_type)
            
            # Draw the node
            node = self.create_oval(x - self.node_radius, y - self.node_radius,
                                  x + self.node_radius, y + self.node_radius,
                                  fill=color, outline="black", width=2, tags=node_id)
            
            # Draw text label
            label = self.create_text(x, y - self.node_radius - 10, 
                                   text=device_name, font=self.font, tags=node_id)
            
            # Draw port label
            port_label = self.create_text(x, y + self.node_radius + 10,
                                        text=f"Port: {port}", font=self.font, tags=node_id)
            
            # Store the items
            self.items[node_id] = {
                'node': node,
                'label': label,
                'port_label': port_label,
                'x': x,
                'y': y,
                'hop': hop
            }
            
            # Draw connection to previous node
            if i > 0:
                prev_node_id = f"node_{i-1}"
                prev_x = self.items[prev_node_id]['x']
                prev_y = self.items[prev_node_id]['y']
                
                # Draw line connecting nodes
                line = self.create_line(prev_x, prev_y + self.node_radius,
                                      x, y - self.node_radius,
                                      fill="black", width=2, arrow=tk.LAST, tags=f"line_{i}")
                
                # Add connection info
                if 'neighbor_port' in path[i-1]:
                    conn_text = self.create_text((prev_x + x) / 2, (prev_y + y) / 2,
                                              text=f"{path[i-1]['neighbor_port']} → {hop.get('exit_port', 'N/A')}",
                                              font=self.font, fill="blue", tags=f"conn_{i}")
        
        # Add target device if path has a neighbor
        if path and 'neighbor' in path[-1]:
            layer = 3  # End device layer
            
            # Calculate position
            current_layer_counts[layer] = current_layer_counts.get(layer, 0) + 1
            position_in_layer = current_layer_counts[layer]
            total_in_layer = self.layer_counts[layer]
            
            # Center the nodes in each layer
            x = (canvas_width / (total_in_layer + 1)) * position_in_layer
            y = (layer + 1) * self.node_spacing_y
            
            # Create the node
            node_id = "node_target"
            
            # Draw the node
            node = self.create_oval(x - self.node_radius, y - self.node_radius,
                                  x + self.node_radius, y + self.node_radius,
                                  fill="#FFB74D", outline="black", width=2, tags=node_id)
            
            # Draw text label
            label = self.create_text(x, y - self.node_radius - 10, 
                                   text=path[-1]['neighbor'], font=self.font, tags=node_id)
            
            # Draw IP label
            ip_label = self.create_text(x, y,
                                      text=target_ip, font=self.font, tags=node_id)
            
            # Draw port label
            port_label = self.create_text(x, y + self.node_radius + 10,
                                        text="Target Device", font=self.font, tags=node_id)
            
            # Store the items
            self.items[node_id] = {
                'node': node,
                'label': label,
                'ip_label': ip_label,
                'port_label': port_label,
                'x': x,
                'y': y
            }
            
            # Draw connection to last hop
            last_node_id = f"node_{len(path)-1}"
            prev_x = self.items[last_node_id]['x']
            prev_y = self.items[last_node_id]['y']
            
            # Draw line connecting nodes
            line = self.create_line(prev_x, prev_y + self.node_radius,
                                  x, y - self.node_radius,
                                  fill="black", width=2, arrow=tk.LAST, tags="line_target")
            
            # Add connection info
            if 'neighbor_port' in path[-1]:
                conn_text = self.create_text((prev_x + x) / 2, (prev_y + y) / 2,
                                          text=f"{path[-1]['neighbor_port']}",
                                          font=self.font, fill="blue", tags="conn_target")
    
    def _get_node_color(self, device_type):
        """Get color based on device type"""
        if 'IOS' in device_type:
            return "#90CAF9"  # Light blue for Cisco IOS
        elif 'NXOS' in device_type:
            return "#80CBC4"  # Teal for Cisco NXOS
        elif 'FORTINET' in device_type:
            return "#A5D6A7"  # Light green for Fortinet
        else:
            return "#E0E0E0"  # Grey for unknown
    
    def _get_tooltip_text(self, hop):
        """Get tooltip text for a hop"""
        lines = []
        for key, value in hop.items():
            if key not in ['hop']:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)
    
    def update_tooltip(self, event):
        """Update tooltip on mouse hover"""
        # Find the closest node
        closest = self.find_closest(event.x, event.y)
        if not closest:
            return
        
        # Get the tags
        tags = self.gettags(closest[0])
        if not tags:
            return
        
        # Find the node id
        node_id = None
        for tag in tags:
            if tag.startswith("node_"):
                node_id = tag
                break
        
        if node_id and node_id in self.items:
            item = self.items[node_id]
            if 'hop' in item:
                # Show tooltip
                tooltip_text = self._get_tooltip_text(item['hop'])
                # TODO: Implement tooltip display


class NetworkTracerGUI(tk.Tk):
    """Main GUI application for network device tracing"""
    
    def __init__(self):
        super().__init__()
        
        # Configure the main window
        self.title("Network Device Tracer")
        self.geometry("900x700")
        self.minsize(800, 600)
        
        # Set application icon from Base64 data
        icondata = '''iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAQAAABpN6lAAAAAAmJLR0QA/4ePzL8AAAAJcEhZcwAAAEgAAABIAEbJaz4AAAAJdnBBZwAAAIAAAACAADDhMZoAAAeySURBVHja7ZxtjFxVGcd/z7zty3Qtpa2wRNpUtEnR+NIaIASrwgeMjYGWxLegQbQhMYRGP9AESZuoiVEjxBiMUTSCETVAg62AYEhroqJrhRpsfIEiuLW2S7vLzO7szM7cOY8futud2e7dPWfm3Duz6/3vl7kz5/zvc/57zj3Pec5zLiRIkCBBggQJEiRIkCBBggQJEvyfQSIhXceVrPBMWuBZ/e8SEECuYQ9XRSKs4Tfs1ee7WgC5ky+SAhRFvUsgBOzW+7tWAPks9wJKnSpTBN4lSJMjx2f0F10pgAzyPHkMU0xQliCCPiCkNccUV+uEL8qUR/NuJY9SYUyKUsVEMASUQCZJcaM/Sp8CXIdSpSDlCJreAKlxRXcKsB5lMurmA8hgdwqQo04ZE3XzgUx3CgABQQzN9wq/AhiJ4//fxQJEPvq7XYAlCI+PkwXxGA9Qty2s8E7ZG49t8Qhg9F4tOtUYZptcFYdp8QyBFBvcKkiOt+gy6gHIt/kTfWSt1x6Xs5FJXrcfNl0uAANsYy05hxqK0bQsGwEgoII6rD6VSvTNj1EAqekoGScBgugHQJw9AOlKRzk+AdyWSX1xuWhxCfBNfmJbVFGVy+RH3uPKHRTA6D51WifoMY7INXGYFpcj9D63CnIxV6rLpNkyfAZFh8nI6ZAHndER8uSs7/cm+plkVOZne8Vs92V1XM+AFBtYSxZbyRXIxtE/45sFakzQ69DjDGWJYdqMzxEKKOi4U416HPHFGB0h6nG4tq7wOcria57HnuFTgNdiE+BMdwrwbGwCHOlOAR5Eokm4mIOAA10pgB7mYY3Ds3zIDPsjS/u0TA6xRS6KuPmH+Ip6fAh6FYBAHqdHNnlmncUk3+PrxutsE8GYldVyLZvIe6YtcpSDpuDf3gQJEiRI0ClInKvRboNslmfktPxdbuu0JZ1p/qAcl3EZl6IU5VOds6NzGSIfYSVKQJkSHRSgc2NwECWgwKSYTqYWdU4AQSnJOHWQqc5J0MkkKUMlxjBaFwoQxYmCJSVAV6CFZ4CsZDPr6Gnzzm9v+JyXj5Jz2jaZC8MIf9FXW2iNY/Gt7OL9Trk+4ahxWkozxDrA6jYDKcrfuJ8HtBqRAHIB32LH9K18jOCAMzJ5zvoBVrUdSRKEl9ipf45AALmEA2zk7ImgGlVqbW9PGCqzu3+abWsInEWaLDkMt+iTngWQPM/wNhTDFCUqUuuOZ/h5rUlplj4y7NAhvwLcw06UOhOMS7ULm96IlPYwxnU6aVPYSgB5K0OkqTNOYbrTatsuTKphCvbLBmiO+/Q7NhXtpsGdZDCUKEoAlPk+TzDWej9QgM/Lx899cZIb2hSgl/dwO2+euZSq3iTftdk/sBNgG8oU41IDanzOHGnTXKDpbImaWpt0NQ7KED+Ujef4V+vl/HXxihaeoKzhUgxlOTu/7vPRfKBH+/1uoGiJbzQMaWWTTS0bV/gipOE82G892ZvnQu95YM+pmZXAbpPORoAUSo2ZTlqyqGGDNGnfKxE1pLX33GXWlwAAwRI5D5aj301Wu8IayUngKCCuyXXLbTksrkkay00A5/Xt8hPAETYCNDspU57u3Dib+MsIbYwFVHwJ8CKzkZZTvOjJ1KcbPv/OmwCzrGrHauOLqQxxraSAUXab/3gy9bhU2SwBcJgva7uu8DTkD2yR1RgC7jNPWdWwJO5nM8hzxmqJaW3uJWziNXnB586ICO9gjRw1J31amiBBggTLFPPMArKS7VzBGyxqj3OYR/V1qxtdyE1ssToLWGCIfXanS2Qt23k3A4sWVM7we355fqD0PAHkZr7KBQ4SFtmjP1jU0NvYa2HmLMa4U3+2CKdwB3fR78B6kl36RPNXcxwh2cU99KIodQIC6ov8GbJ8UMzCXpfczZfocWLt4cNS4PCCrF9jN1kn1n52yCscbWJpungXB8mg1ChTsXwbXIocvdwQvhEh7+VxBKVK2fIdc0KKHBmu16OhRT7Ez6EFVmFr4yZqswA/5kaUMkUpO0TqRbP8UW8N/Xk/H8BQoSAuCRGiOX6tu0J/PsQWDGWKjqw9PKx75hVAenmZFUwx6v4+MK1z9fy7spJnmAwVRqXizFpi6/yxfVnLSwhlxqTsxgk6otfPXjWuBi9mAMOEu6EgadaE/DRIlnqLrPnQWeNSUtOszpBVjVeNAsyM/tbCnxL6/VnWlhY8oZmkmenR3wprk6Vz4wG1Vo+rLrisrEVyZNIL61wB6pFEf6N5u6QXW5OYYKcN6DQSATptQKeRCNBpAzqNRICGz8U2Mv+UMJ+8nUB6PbS22+sZm9G0t9UggI5wrGXSk2Y05JcTnGqZ9V8mzNd/Gaf3kTThHyECAA+1TBp6ol+1Ddb9oaxVHvFja3M8oI9fyaoWcvaO8zETmjojK3la+lpgPcYnTGjis7yRpyTVwqB9gU83nj9vTi8s80k94Ux5gtvNAplDWuBmdX+/yKvcYRbI+9YRblH3s+T/5AvNx+/nbo4W5DHSsoFeS8Iij3CXGVmk1Kjsp1fWW58xGOOn3B36VJnBKTnACllvlwwFnOZB9po5z455V7GSlnVW0dYy/zbWy2fJyDr6LAqWGLZ/SYLkxO7wxjjHzdJI9EqQIEGCBAkSJIgH/wOhy7cnpv+HNgAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAxMC0wMi0xMVQxMjo1MDoxOC0wNjowMKdwCasAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMDktMTAtMjJUMjM6MjM6NTYtMDU6MDAtj0NVAAAAAElFTkSuQmCC'''
        icon = tk.PhotoImage(data=icondata)
        self.iconphoto(True, icon)
        
        # Check if running on Windows or Linux
        self.is_windows = sys.platform.startswith('win')
        
        # Set theme based on platform
        if self.is_windows:
            self.configure(bg=LIGHT_BG)
            text_color = "black"
        else:
            self.configure(bg=DARK_BG)
            text_color = TEXT_COLOR
        
        # Create member variables
        self.tracer = DeviceTracer(progress_callback=self.update_progress)
        self.current_filepath = None
        
        # Create and configure main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create sections
        self.create_input_section(main_frame)
        self.create_progress_section(main_frame)
        self.create_output_section(main_frame)
        
        # Configure style
        self.configure_styles()
        
        # Set up threading
        self.trace_thread = None
        self.stop_thread = False
    
    def configure_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        
        # Main style configuration
        if self.is_windows:
            # Try to use 'vista' theme, fall back to 'winnative' if not available
            available_themes = style.theme_names()
            if 'vista' in available_themes:
                style.theme_use('vista')
            elif 'winnative' in available_themes:
                style.theme_use('winnative')
            else:
                style.theme_use('default')
        else:
            style.theme_use('clam')
        
        # Button styles
        style.configure('TButton', padding=6)
        style.configure('Primary.TButton', background=ACCENT_COLOR)
        
        # Label styles
        style.configure('TLabel', padding=2)
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'))
        
        # Frame styles
        style.configure('TFrame', background=LIGHT_BG if self.is_windows else DARK_BG)
        
        # Entry styles
        style.configure('TEntry', padding=5)
        
        # Progressbar styles
        style.configure('TProgressbar', 
                        background=ACCENT_COLOR, 
                        troughcolor=LIGHT_BG if self.is_windows else DARK_BG)
    
    def create_input_section(self, parent):
        """Create the input section of the GUI"""
        input_frame = ttk.LabelFrame(parent, text="Connection Settings")
        input_frame.pack(fill=tk.X, expand=False, pady=5)
        
        # Create a grid for the inputs
        input_grid = ttk.Frame(input_frame)
        input_grid.pack(fill=tk.X, expand=True, padx=10, pady=5)
        
        # Start Device
        ttk.Label(input_grid, text="Start Device:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.start_device_var = tk.StringVar()
        ttk.Entry(input_grid, textvariable=self.start_device_var).grid(row=0, column=1, sticky=tk.EW, pady=2)
        
        # Target Device
        ttk.Label(input_grid, text="Target Device:").grid(row=0, column=2, sticky=tk.W, pady=2, padx=(10, 0))
        self.target_device_var = tk.StringVar()
        ttk.Entry(input_grid, textvariable=self.target_device_var).grid(row=0, column=3, sticky=tk.EW, pady=2)
        
        # Username
        ttk.Label(input_grid, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.username_var = tk.StringVar()
        ttk.Entry(input_grid, textvariable=self.username_var).grid(row=1, column=1, sticky=tk.EW, pady=2)
        
        # Authentication type
        self.auth_type = tk.StringVar(value="password")
        ttk.Label(input_grid, text="Auth Type:").grid(row=1, column=2, sticky=tk.W, pady=2, padx=(10, 0))
        auth_frame = ttk.Frame(input_grid)
        auth_frame.grid(row=1, column=3, sticky=tk.EW, pady=2)
        
        ttk.Radiobutton(auth_frame, text="Password", variable=self.auth_type, 
                        value="password", command=self.toggle_auth_type).pack(side=tk.LEFT)
        ttk.Radiobutton(auth_frame, text="SSH Key", variable=self.auth_type, 
                        value="key", command=self.toggle_auth_type).pack(side=tk.LEFT, padx=(10, 0))
        
        # Password or Key File
        self.auth_label = ttk.Label(input_grid, text="Password:")
        self.auth_label.grid(row=2, column=0, sticky=tk.W, pady=2)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(input_grid, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=2, column=1, sticky=tk.EW, pady=2)
        
        self.key_file_var = tk.StringVar()
        self.key_file_entry = ttk.Entry(input_grid, textvariable=self.key_file_var)
        
        self.key_browse_button = ttk.Button(input_grid, text="Browse...", command=self.browse_key_file)
        
        # Display options
        ttk.Label(input_grid, text="Display:").grid(row=2, column=2, sticky=tk.W, pady=2, padx=(10, 0))
        
        display_frame = ttk.Frame(input_grid)
        display_frame.grid(row=2, column=3, sticky=tk.EW, pady=2)
        
        self.display_type = tk.StringVar(value="full_path")
        ttk.Radiobutton(display_frame, text="Full Path", variable=self.display_type, 
                        value="full_path").pack(side=tk.LEFT)
        ttk.Radiobutton(display_frame, text="End Port Only", variable=self.display_type, 
                        value="end_port").pack(side=tk.LEFT, padx=(10, 0))
        
        # Action buttons
        action_frame = ttk.Frame(input_frame)
        action_frame.pack(fill=tk.X, expand=True, padx=10, pady=10)
        
        self.trace_button = ttk.Button(action_frame, text="Trace Device", 
                                     command=self.start_trace, style='Primary.TButton')
        self.trace_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(action_frame, text="Save Results", 
                  command=self.save_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(action_frame, text="Load Results", 
                  command=self.load_results).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(action_frame, text="Clear", 
                  command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        # Make grid columns expand
        for i in range(4):
            input_grid.columnconfigure(i, weight=1)
    
    def create_progress_section(self, parent):
        """Create the progress section of the GUI"""
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill=tk.X, expand=False, pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, 
                                      length=100, mode='determinate')
        self.progress.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=(0, 5))
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(progress_frame, textvariable=self.status_var, width=30)
        self.status_label.pack(side=tk.LEFT)
    
    def create_output_section(self, parent):
        """Create the output section of the GUI"""
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Text output tab
        text_frame = ttk.Frame(notebook)
        notebook.add(text_frame, text="Text Output")
        
        self.output_text = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, 
                                                   font=('Courier New', 10))
        self.output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Visual output tab
        visual_frame = ttk.Frame(notebook)
        notebook.add(visual_frame, text="Visual Output")
        
        # Create canvas for network visualization
        self.canvas = NetworkCanvas(visual_frame, bg='white', 
                                  highlightthickness=1, highlightbackground=BORDER_COLOR)
        self.canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add canvas event bindings
        self.canvas.bind("<Configure>", self.on_canvas_resize)
    
    def toggle_auth_type(self):
        """Toggle between password and key file authentication"""
        if self.auth_type.get() == "password":
            # Show password field, hide key file field
            self.auth_label.config(text="Password:")
            self.key_file_entry.grid_forget()
            self.key_browse_button.grid_forget()
            self.password_entry.grid(row=2, column=1, sticky=tk.EW, pady=2)
        else:
            # Show key file field, hide password field
            self.auth_label.config(text="Key File:")
            self.password_entry.grid_forget()
            self.key_file_entry.grid(row=2, column=1, sticky=tk.EW, pady=2)
            self.key_browse_button.grid(row=2, column=1, sticky=tk.E, pady=2, padx=(0, 0))
    
    def browse_key_file(self):
        """Browse for SSH key file"""
        filename = filedialog.askopenfilename(
            title="Select SSH Key File",
            filetypes=(("All Files", "*.*"), ("PEM Files", "*.pem"), ("PPK Files", "*.ppk"))
        )
        if filename:
            self.key_file_var.set(filename)
    
    def update_progress(self, message, percentage=None):
        """Update progress bar and status message"""
        self.status_var.set(message)
        
        if percentage is not None:
            self.progress['value'] = percentage
        
        # Update UI
        self.update_idletasks()
    
    def start_trace(self):
        """Start the device tracing process in a separate thread"""
        # Validate inputs
        start_device = self.start_device_var.get().strip()
        target_device = self.target_device_var.get().strip()
        username = self.username_var.get().strip()
        
        if not start_device or not target_device or not username:
            messagebox.showerror("Input Error", "Start device, target device, and username are required")
            return
        
        # Get password or key file
        if self.auth_type.get() == "password":
            password = self.password_var.get()
            key_file = None
            if not password:
                messagebox.showerror("Input Error", "Password is required for password authentication")
                return
        else:
            password = None
            key_file = self.key_file_var.get()
            if not key_file:
                messagebox.showerror("Input Error", "Key file is required for key-based authentication")
                return
        
        # Clear previous results
        self.clear_results(clear_input=False)
        
        # Disable trace button during operation
        self.trace_button.config(state=tk.DISABLED)
        
        # Get display type
        end_port_only = self.display_type.get() == "end_port"
        
        # Start tracing in a separate thread
        self.stop_thread = False
        self.trace_thread = threading.Thread(
            target=self.run_trace,
            args=(start_device, target_device, username, password, key_file, end_port_only)
        )
        self.trace_thread.daemon = True
        self.trace_thread.start()
    
    def run_trace(self, start_device, target_device, username, password, key_file, end_port_only):
        """Run the trace operation in a separate thread"""
        try:
            # Reset progress
            self.update_progress("Starting trace...", 0)
            
            # Create the network device
            device = NetworkDevice(
                hostname=start_device,
                username=username,
                password=password,
                key_file=key_file,
                progress_callback=self.update_progress
            )
            
            # Connect to the device
            if not device.connect():
                self.update_progress(f"Failed to connect to {start_device}", 0)
                messagebox.showerror("Connection Error", f"Failed to connect to {start_device}")
                self.trace_button.config(state=tk.NORMAL)
                return
            
            # Prepare credentials for subsequent devices
            credentials = {
                'username': username,
                'password': password,
                'key_file': key_file
            }
            
            # Trace the device
            self.update_progress(f"Tracing path to {target_device}...", 30)
            path = self.tracer.trace_device(
                start_device=device,
                target_ip=target_device,
                credentials=credentials,
                end_port_only=end_port_only
            )
            
            # Check if operation was stopped
            if self.stop_thread:
                self.update_progress("Operation cancelled", 0)
                self.trace_button.config(state=tk.NORMAL)
                return
            
            # Show results
            if not path and not self.tracer.end_device_port:
                self.update_progress("No path found to the target device", 0)
                messagebox.showinfo("Trace Results", "No path found to the target device")
            else:
                self.update_progress("Trace completed successfully", 100)
                self.display_results(end_port_only)
            
        except Exception as e:
            self.update_progress(f"Error during trace: {str(e)}", 0)
            messagebox.showerror("Trace Error", f"An error occurred: {str(e)}")
            logger.exception("Error during trace")
        finally:
            # Re-enable the trace button
            self.trace_button.config(state=tk.NORMAL)
    
    def display_results(self, end_port_only):
        """Display the trace results"""
        # Clear previous output
        self.output_text.delete(1.0, tk.END)
        
        if end_port_only and self.tracer.end_device_port:
            # Display only end port information
            output = f"Target IP: {self.tracer.target_ip}\n\n"
            output += "=== DEVICE PORT INFORMATION ===\n\n"
            output += f"Device: {self.tracer.end_device_port['device_name']} ({self.tracer.end_device_port['device_ip']})\n"
            output += f"Port: {self.tracer.end_device_port['port']}\n"
            output += f"VLAN: {self.tracer.end_device_port['vlan']}\n"
            output += f"Port Type: {self.tracer.end_device_port['port_type']}\n"
            
            self.output_text.insert(tk.END, output)
        else:
            # Display full path information
            if self.tracer.path:
                # Show the text diagram
                diagram = self.tracer.create_path_diagram()
                self.output_text.insert(tk.END, diagram)
                
                # Add detailed info
                self.output_text.insert(tk.END, "\n\n")
                self.output_text.insert(tk.END, self.tracer.generate_detailed_path_diagram())
            else:
                self.output_text.insert(tk.END, "No path data available")
        
        # Update canvas visualization
        self.canvas.draw_path(self.tracer.path, self.tracer.target_ip)
    
    def save_results(self):
        """Save the trace results to a file"""
        if not self.tracer.path and not self.tracer.end_device_port:
            messagebox.showinfo("Save Results", "No results to save")
            return
        
        # Ask user what format to save in
        format_choice = messagebox.askyesno(
            "Save Format", 
            "Save in JSON format? (Yes for JSON, No for Text)"
        )
        
        if format_choice:
            # Save as JSON
            filetypes = [('JSON files', '*.json'), ('All files', '*.*')]
            default_ext = '.json'
            method = self.tracer.save_json_to_file
        else:
            # Save as text
            filetypes = [('Text files', '*.txt'), ('All files', '*.*')]
            default_ext = '.txt'
            method = lambda f: self.tracer.save_path_to_file(self.tracer.target_ip, f)
        
        # Ask for filename
        filepath = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=filetypes,
            initialdir=os.path.join(os.getcwd(), "path_traces")
        )
        
        if filepath:
            try:
                saved_path = method(filepath)
                if saved_path:
                    self.current_filepath = saved_path
                    messagebox.showinfo("Save Results", f"Results saved to {saved_path}")
                else:
                    messagebox.showerror("Save Error", "Failed to save results")
            except Exception as e:
                messagebox.showerror("Save Error", f"Error saving results: {str(e)}")
                logger.exception("Error saving results")
    
    def load_results(self):
        """Load trace results from a file"""
        filepath = filedialog.askopenfilename(
            filetypes=[
                ('JSON files', '*.json'),
                ('Text files', '*.txt'),
                ('All files', '*.*')
            ],
            initialdir=os.path.join(os.getcwd(), "path_traces")
        )
        
        if not filepath:
            return
        
        try:
            # Check if it's a JSON file
            if filepath.lower().endswith('.json'):
                # Load from JSON
                json_data = DeviceTracer.load_json_from_file(filepath)
                if not json_data:
                    messagebox.showerror("Load Error", "Failed to load JSON data")
                    return
                
                # Create a new tracer with the loaded data
                self.tracer = DeviceTracer(progress_callback=self.update_progress)
                self.tracer.load_from_json(json_data)
                
                # Display the results
                self.current_filepath = filepath
                end_port_only = not self.tracer.path or len(self.tracer.path) <= 1
                self.display_results(end_port_only)
                
                messagebox.showinfo("Load Results", "Results loaded successfully")
            else:
                # Load text file to display only
                with open(filepath, 'r') as f:
                    content = f.read()
                
                # Clear previous output
                self.output_text.delete(1.0, tk.END)
                self.output_text.insert(tk.END, content)
                
                # Clear canvas
                self.canvas.clear()
                
                messagebox.showinfo("Load Results", 
                                  "Text file loaded. Note: Visualization is only available for JSON files.")
        except Exception as e:
            messagebox.showerror("Load Error", f"Error loading results: {str(e)}")
            logger.exception("Error loading results")
    
    def clear_results(self, clear_input=True):
        """Clear all results and optionally input fields"""
        # Clear output text
        self.output_text.delete(1.0, tk.END)
        
        # Clear canvas
        self.canvas.clear()
        
        # Reset progress
        self.progress['value'] = 0
        self.status_var.set("Ready")
        
        # Reset tracer
        self.tracer = DeviceTracer(progress_callback=self.update_progress)
        self.current_filepath = None
        
        # Clear input fields if requested
        if clear_input:
            self.start_device_var.set("")
            self.target_device_var.set("")
            self.password_var.set("")
            self.key_file_var.set("")
    
    def on_canvas_resize(self, event):
        """Handle canvas resize event"""
        # Redraw the path when canvas size changes
        self.canvas.draw_path(self.tracer.path, self.tracer.target_ip)


def main():
    """Main entry point"""
    # Set up exception logging
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logger.error("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = handle_exception
    
    # Start the application
    app = NetworkTracerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
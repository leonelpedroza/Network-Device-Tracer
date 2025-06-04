# Network Device Tracer

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Python-Networking-blue?style=for-the-badge&logo=python&logoColor=white">
</p>


## 📖 History

How often has a network support engineer had to deal with a remote connection without knowing where the device to be diagnosed is connected, whether the port is configured correctly or whether some fundamental parameter is missing, or how many connection errors, especially at the physical level, are occurring?

There's no way to ask the end user, who usually only knows how to log in to the device and manage their software.

This tool is intended to help locate the physical port in Cisco and Fortinet networks, and it has worked well for me in most cases.


## 🚀 Introduction

A user-friendly graphical interface for tracing devices through networks by querying ARP and MAC address tables on Cisco and Fortinet devices.

![](https://github.com/leonelpedroza/Network-Device-Tracer/blob/main/pantallazo.png)

## 🌟 Features

- **Intuitive Graphical Interface**: Easy-to-use GUI for network path discovery
- **Multi-vendor Support**: Works with Cisco IOS, IOS-XE, NX-OS, and Fortinet devices
- **Flexible Authentication**: Support for both password and key-based SSH authentication
- **Path Visualization**: Visual and text-based network path diagrams
- **Progress Tracking**: Real-time progress tracking during operations
- **Results Management**: Save and load trace results in JSON or text format
- **Cross-platform**: Works on Windows 10/11 and Linux

## 📸 Screenshots

*[Add screenshots of the application interface and visualizations here]*

## 🔧 Installation

### Prerequisites

- Python 3.6+
- Required Python packages:
  - paramiko
  - netmiko
  - tkinter (usually comes with Python)

### Setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/network-device-tracer.git
   cd network-device-tracer
   ```

2. Install required dependencies:
   ```
   pip install paramiko netmiko
   ```

3. Run the application:
   ```
   python GUI-tracker.py
   ```

### Creating a Standalone Executable (Windows)

```
pip install pyinstaller
pyinstaller --onefile --windowed GUI-tracker.py
```

The executable will be created in the `dist` folder.

## 📖 Usage Guide

1. **Configure Connection Settings**:
   - Enter the IP address of your starting device (typically a Layer 3 switch or router)
   - Enter the target device IP address
   - Provide authentication credentials (username and password or SSH key)
   - Select display type (Full Path or End Port Only)

2. **Start Tracing**:
   - Click "Trace Device" to begin the trace
   - Watch real-time progress in the status bar

3. **View Results**:
   - View text output with detailed hop information
   - See visual network path diagram in the visualization tab

4. **Save/Load Results**:
   - Save results as JSON for later visualization or as text reports
   - Load previously saved trace results

## 🔍 Technical Details

- **Discovery Process**: The tool uses standard network protocols to discover the path:
  - ARP tables to find MAC addresses from IP addresses
  - MAC address tables to find which port a device is connected to
  - CDP/LLDP to find neighbor devices
  
- **Auto-detection**: Automatically detects device types and adapts commands accordingly

- **Retry Logic**: Implements exponential backoff for connection retries

- **JSON Serialization**: All trace results can be serialized to JSON for integration with other tools

## 🛡️ Security Considerations

- Credentials are never stored persistently
- SSH connections use industry-standard security
- Consider using SSH keys instead of passwords for enhanced security
- The tool requires privileged access to network devices

## 🚀 Advanced Usage

### Command-Line Arguments (Future Enhancement)

```
python GUI-tracker.py --start-device 192.168.1.1 --target 10.0.0.5 --username admin
```

### Programmatic API

The core `DeviceTracer` and `NetworkDevice` classes can be imported and used in other Python applications:

```python
from GUI-tracker import DeviceTracer, NetworkDevice

device = NetworkDevice(hostname="192.168.1.1", username="admin", password="password")
tracer = DeviceTracer()
path = tracer.trace_device(device, "10.0.0.5")
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Contact

*Leonel Giovanny Pedroza Renteria*

---

*This tool is for network administrators and engineers. Always ensure you have proper authorization before querying network devices.*

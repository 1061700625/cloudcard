"""
设备信息收集模块
"""
import socket
import uuid
import platform
import hashlib


def get_device_sn() -> str:
    """
    获取设备序列号
    
    Returns:
        设备序列号（基于硬件信息生成的唯一标识）
    """
    # 尝试获取真实的硬件序列号
    try:
        # Windows
        if platform.system() == "Windows":
            import wmi
            c = wmi.WMI()
            for item in c.Win32_BIOS():
                return item.SerialNumber.strip()
        # Linux
        elif platform.system() == "Linux":
            try:
                with open('/etc/machine-id', 'r') as f:
                    return f.read().strip()
            except:
                try:
                    with open('/var/lib/dbus/machine-id', 'r') as f:
                        return f.read().strip()
                except:
                    pass
        # macOS
        elif platform.system() == "Darwin":
            import subprocess
            output = subprocess.check_output(['system_profiler', 'SPHardwareDataType'])
            for line in output.decode('utf-8').split('\n'):
                if 'Serial Number' in line:
                    return line.split(':')[1].strip()
    except:
        pass
    
    # 如果无法获取真实序列号，则基于MAC地址和硬件信息生成一个
    mac = uuid.getnode()
    machine_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}-{mac}"
    device_sn = hashlib.sha256(machine_info.encode()).hexdigest()[:32]
    
    return device_sn


def get_ip_address() -> str:
    """
    获取本机IP地址
    
    Returns:
        本机IP地址
    """
    try:
        # 创建一个UDP socket连接到外部地址（不会真正发送数据）
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except:
        # 如果无法获取，返回回环地址
        return "127.0.0.1"


def get_device_info() -> dict:
    """
    获取设备完整信息
    
    Returns:
        设备信息字典
    """
    return {
        'device_sn': get_device_sn(),
        'ip_address': get_ip_address(),
        'hostname': platform.node(),
        'platform': platform.system(),
        'platform_release': platform.release(),
        'platform_version': platform.version(),
        'architecture': platform.machine(),
        'processor': platform.processor()
    }


if __name__ == "__main__":
    # 测试
    print("设备序列号:", get_device_sn())
    print("IP地址:", get_ip_address())
    print("\n完整设备信息:")
    info = get_device_info()
    for key, value in info.items():
        print(f"  {key}: {value}")

import platform
import socket
import psutil
from datetime import datetime

AGENT_VERSION = "1.0.0"

_GB = 1024 ** 3


def get_device_info():
    """Collect static device profile sent at agent registration."""
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = None

    # Best-effort local IPv4 address (first non-loopback interface).
    ip_address = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    os_ver = f"{platform.system()} {platform.release()}"
    os_build = platform.version()
    cpu_model = platform.processor() or platform.machine()
    try:
        cpu_cores = psutil.cpu_count(logical=True)
        ram_gb = round(psutil.virtual_memory().total / _GB, 1)
        disk_total_gb = round(psutil.disk_usage('/').total / _GB, 1)
        disk_free_gb = round(psutil.disk_usage('/').free / _GB, 1)
    except Exception:
        cpu_cores = ram_gb = disk_total_gb = disk_free_gb = None

    return {
        "hostname": hostname,
        "os_version": os_ver,
        "os_build": os_build,
        "cpu_model": cpu_model,
        "cpu_cores": cpu_cores,
        "ram_gb": ram_gb,
        "disk_total_gb": disk_total_gb,
        "disk_free_gb": disk_free_gb,
        "ip_address": ip_address,
        "agent_version": AGENT_VERSION,
    }


def get_system_metrics():
    cpu_usage = psutil.cpu_percent(interval=1)
    ram_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent if psutil.disk_usage('/') else None
    return {
        "cpu_usage": cpu_usage,
        "ram_usage": ram_usage,
        "disk_usage": disk_usage,
        "timestamp": datetime.utcnow().isoformat()
    }

def get_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
        try:
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "cpu_percent": proc.info['cpu_percent'],
                "memory_percent": proc.info['memory_percent'],
                "create_time": datetime.fromtimestamp(proc.info['create_time']).isoformat()
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

def get_network_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            connections.append({
                "fd": conn.fd,
                "family": conn.family.name if conn.family else None,
                "type": conn.type.name if conn.type else None,
                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid
            })
        except Exception:
            pass
    return connections

import psutil
from datetime import datetime

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

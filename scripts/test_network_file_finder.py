import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from endpoint_agent.monitors.network_monitor import NetworkMonitor

def test_network_monitor_file_finder():
    print("Testing NetworkMonitor process file handle inspection...")
    files = NetworkMonitor.find_uploading_files()
    print(f"Active process file candidates detected: {len(files)}")
    for f in files:
        print(f" -> Process: {f['process_name']} (PID {f['pid']}) | File: {f['filename']} in {f['folder']}")
    print("✓ NetworkMonitor file inspection ran without error!")

if __name__ == "__main__":
    test_network_monitor_file_finder()

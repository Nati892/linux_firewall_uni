# server.py
import socket
import threading
import time
import psutil
import json
from datetime import datetime

class PerformanceServer:
    def __init__(self, host='0.0.0.0', tcp_port=5000, udp_port=5001):
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.tcp_socket = None
        self.udp_socket = None
        self.running = False
        self.cpu_stats = []
        self.active_connections = 0
        self.max_connections = 0

    def start(self):
        self.running = True
        # Start CPU monitoring in a separate thread
        threading.Thread(target=self._monitor_cpu).start()
        
        # Start TCP and UDP servers in separate threads
        tcp_thread = threading.Thread(target=self._run_tcp_server)
        udp_thread = threading.Thread(target=self._run_udp_server)
        
        tcp_thread.start()
        udp_thread.start()
        
        print(f"Server started on {self.host}")
        print(f"TCP port: {self.tcp_port}")
        print(f"UDP port: {self.udp_port}")

    def _monitor_cpu(self):
        while self.running:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory_percent = psutil.virtual_memory().percent
            self.cpu_stats.append({
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'active_connections': self.active_connections
            })
            time.sleep(1)

    def _run_tcp_server(self):
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp_socket.bind((self.host, self.tcp_port))
        self.tcp_socket.listen(50)  # Increased backlog for concurrent connections

        while self.running:
            client_socket, addr = self.tcp_socket.accept()
            threading.Thread(target=self._handle_tcp_client, args=(client_socket, addr)).start()

    def _run_udp_server(self):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((self.host, self.udp_port))

        while self.running:
            data, addr = self.udp_socket.recvfrom(65535)
            if data:
                self.udp_socket.sendto(data, addr)

    def _handle_tcp_client(self, client_socket, addr):
        self.active_connections += 1
        self.max_connections = max(self.max_connections, self.active_connections)
        
        try:
            while True:
                data = client_socket.recv(65535)
                if not data:
                    break
                client_socket.send(data)  # Echo back for throughput testing
        except:
            pass
        finally:
            self.active_connections -= 1
            client_socket.close()

    def stop(self):
        self.running = False
        if self.tcp_socket:
            self.tcp_socket.close()
        if self.udp_socket:
            self.udp_socket.close()
        
        # Save CPU stats to file
        stats = {
            'cpu_stats': self.cpu_stats,
            'max_concurrent_connections': self.max_connections
        }
        with open('server_stats.json', 'w') as f:
            json.dump(stats, f, indent=2)

if __name__ == "__main__":
    server = PerformanceServer()
    try:
        server.start()
        input("Press Enter to stop the server...\n")
    finally:
        server.stop()
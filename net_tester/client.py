import socket
import time
import statistics
import json
from datetime import datetime

# Configuration
SERVER_HOST = '192.168.1.86'  # Change this to your server's IP
TCP_PORT = 5000
TEST_RUNS = 15
TEST_DURATION = 2  # seconds
packet_sizes = [1024, 65535]  # Test packet sizes

class PerformanceTest:
    def __init__(self, server_host=SERVER_HOST, tcp_port=TCP_PORT):
        self.server_host = server_host
        self.tcp_port = tcp_port
        self.test_runs = TEST_RUNS
        self.results = []  # Store test results

    def run_tcp_test(self, packet_size, duration=TEST_DURATION, direction="outbound"):
        """Run TCP throughput test with specified packet size"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)  # 5 second timeout
        
        try:
            sock.connect((self.server_host, self.tcp_port))
            data = b'x' * packet_size
            bytes_transferred = 0
            start_time = time.time()
            
            while time.time() - start_time < duration:
                if direction == "outbound":
                    sock.send(data)
                    sock.recv(packet_size)  # Receive echo
                else:
                    sock.send(b'x')  # Small trigger packet
                    sock.recv(packet_size)  # Receive large packet
                
                bytes_transferred += packet_size

        except Exception as e:
            print(f"TCP error: {e}")
            return 0
        finally:
            sock.close()

        elapsed_time = time.time() - start_time
        if elapsed_time > 0 and bytes_transferred > 0:
            throughput = (bytes_transferred * 8) / (1024 * 1024 * elapsed_time)  # Mbps
        else:
            throughput = 0
        
        return throughput

    def run_tests(self):
        """Run test suite with various packet sizes"""
        print("\nStarting TCP Performance Tests...")
        print(f"Running {self.test_runs} iterations per test")
        print(f"Test duration: {TEST_DURATION} seconds")
        
        self.results = []  # Clear previous results
        
        for direction in ["outbound", "inbound"]:
            print(f"\n=== Testing {direction} traffic ===")
            for size in packet_sizes:
                print(f"\nPacket size: {size} bytes")
                test_results = []
                
                for i in range(self.test_runs):
                    throughput = self.run_tcp_test(size, direction=direction)
                    test_results.append(throughput)
                    print(f"Run {i+1}: {throughput:.2f} Mbps")
                
                avg_throughput = statistics.mean(test_results)
                std_dev = statistics.stdev(test_results)
                max_throughput = max(test_results)
                min_throughput = min(test_results)
                
                # Store results
                self.results.append({
                    'type': 'sequential',
                    'protocol': 'tcp',
                    'direction': direction,
                    'packet_size': size,
                    'average_throughput': avg_throughput,
                    'max_throughput': max_throughput,
                    'min_throughput': min_throughput,
                    'stddev_throughput': std_dev
                })
                
                print(f"\nResults for {size} bytes {direction}:")
                print(f"Average Throughput: {avg_throughput:.2f} Mbps")
                print(f"Maximum Throughput: {max_throughput:.2f} Mbps")
                print(f"Minimum Throughput: {min_throughput:.2f} Mbps")
                print(f"Standard Deviation: {std_dev:.2f} Mbps")
                print("-" * 50)

    def generate_report(self):
        """Generate and save detailed performance report"""
        if not self.results:
            print("No test results available. Please run tests first.")
            return

        report = {
            'timestamp': datetime.now().isoformat(),
            'config': {
                'server_host': self.server_host,
                'tcp_port': self.tcp_port,
                'test_runs': self.test_runs,
                'test_duration': TEST_DURATION,
                'packet_sizes': packet_sizes
            },
            'results': {
                'outbound': {},
                'inbound': {}
            }
        }

        # Organize results by direction and packet size
        for result in self.results:
            direction = result['direction']
            packet_size = result['packet_size']
            
            if packet_size not in report['results'][direction]:
                report['results'][direction][packet_size] = []
            
            report['results'][direction][packet_size].append({
                'average_throughput': result['average_throughput'],
                'max_throughput': result['max_throughput'],
                'min_throughput': result['min_throughput'],
                'stddev_throughput': result['stddev_throughput']
            })

        # Save report to file
        filename = f'performance_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nReport saved to {filename}")

        # Print summary
        print("\n=== Performance Test Summary ===")
        for direction in ['outbound', 'inbound']:
            print(f"\n{direction.upper()} Traffic Results:")
            for packet_size in packet_sizes:
                results = report['results'][direction].get(packet_size, [])
                if results:
                    print(f"\nPacket Size: {packet_size} bytes")
                    result = results[0]  # Take the first result set
                    print(f"Average Throughput: {result['average_throughput']:.2f} Mbps")
                    print(f"Maximum Throughput: {result['max_throughput']:.2f} Mbps")
                    print(f"Minimum Throughput: {result['min_throughput']:.2f} Mbps")
                    print(f"Standard Deviation: {result['stddev_throughput']:.2f} Mbps")


if __name__ == "__main__":
    print(f"\nConnecting to server at {SERVER_HOST}")
    print(f"TCP Port: {TCP_PORT}")
    for i in range(3):
        test_suite = PerformanceTest()
        test_suite.run_tests()
        test_suite.generate_report()
import argparse
import os
import subprocess
import sys
import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = "8000"
SOURCE_PORT = "12345"
PACKET_COUNT = "500"

def check_privileges():
    if os.geteuid() != 0:
        print("🔴 root priveleges required to run hping3. 🔴")
        print("run again with 'sudo'.")
        sys.exit(1)

def print_info(traffic_type, command):
    """Prints information about the traffic being generated."""
    print(f"    𓆝 𓆟 𓆞 𓆝 𓆟")
    print(f" Generating {traffic_type} traffic...")
    print(f"   Target: {TARGET_IP}")
    print(f"   Command: {' '.join(command)}")
    print("-" * 20)

def generate_syn_flood():
    command = ["hping3", "-S", "-p", TARGET_PORT, "-s", SOURCE_PORT, "-k", "-i", "u100", TARGET_IP]
    print_info("SYN flood",command)
    subprocess.run(command, check= True)

def generate_port_scan():
    command = ["hping3", "-A", "-p", TARGET_PORT, "-s", SOURCE_PORT, "-k", "-i", "u100", TARGET_IP]
    print_info("Port scan",command)
    subprocess.run(command, check= True)

def generate_anomalous_traffic():
    command = ["hping3", "-A", "-p", TARGET_PORT, "-d", "45000", "-i", "s2", "-c", "30", "--rand-source", TARGET_IP]
    print_info("Anomalous (Low-and-Slow)", command)
    subprocess.run(command, check=True)

def generate_normal_traffic():
    command = ["curl", "-s", f"http://{TARGET_IP}:{TARGET_PORT}"]
    print_info("Normal (HTTP GET Requests)", command)
    
    check_server_cmd = f"curl -s -o /dev/null -w '%{{http_code}}' http://{TARGET_IP}:{TARGET_PORT}"
    try:
        http_code = subprocess.check_output(check_server_cmd, shell=True, timeout=2).decode('utf-8')
        if http_code not in ["200", "301", "404"]: 
             raise ConnectionRefusedError
    except (subprocess.TimeoutExpired, ConnectionRefusedError, subprocess.CalledProcessError):
        print(f"⚠️  Warning: Could not connect to a web server at http://{TARGET_IP}:{TARGET_PORT}")
        print(f"   Please run 'python3 -m http.server {TARGET_PORT}' in another terminal for best results.")
        return

    for i in range(5):
        print(f"   Sending request {i+1}/5...")
        subprocess.run(command, check=False, stdout=subprocess.DEVNULL)
        time.sleep(1)
    print("✅ Normal traffic generated.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="🚀 Network Traffic Generator for NIDS Testing.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    
    traffic_types = {
        "syn-flood": generate_syn_flood,
        "port-scan": generate_port_scan,
        "anomalous": generate_anomalous_traffic,
        "normal": generate_normal_traffic
    }
    
    parser.add_argument(
        "type",
        choices=traffic_types.keys(),
        help="Type of traffic to generate."
    )
    
    args = parser.parse_args()
    
    
    if args.type != "normal":
        check_privileges()
        
    traffic_types[args.type]()

        

import argparse
import os
import subprocess
import sys
import time
import threading
from comnetsemu.cli import CLI, spawnXtermDocker
from comnetsemu.net import Containernet, VNFManager
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.node import Controller

# Function to add a service container to the VNFManager
def add_service_container(manager, name, role, image, shared_dir):
    return manager.addContainer(
        name, role, image, '', docker_args={
            'volumes': {
                shared_dir: {'bind': '/home/pcap/', 'mode': 'rw'}
            }
        }
    )

# Functions to start various service servers
def start_video_server():
    subprocess.run([
        'docker', 'exec', '-it', 'video_server',
        'bash', '-c', 'cd /home && python3 video_streaming.py'
    ])

def start_audio_server():
    subprocess.run([
        'docker', 'exec', '-it', 'audio_server',
        'bash', '-c', 'cd /home && python3 audio_streaming.py'
    ])

def start_file_server():
    subprocess.run([
        'docker', 'exec', '-it', 'file_server',
        'bash', '-c', 'cd /home && python3 file_transfer_server.py'
    ])

def start_web_server():
    subprocess.run([
        'docker', 'exec', '-it', 'web_server',
        'bash', '-c', 'cd /home && python3 web_server.py'
    ])

# Functions to start various service clients
def start_video_client():
    subprocess.run([
        'docker', 'exec', '-it', 'video_client',
        'bash', '-c', 'cd /home && python3 get_video_streamed.py'
    ])

def start_audio_client():
    subprocess.run([
        'docker', 'exec', '-it', 'audio_client',
        'bash', '-c', 'cd /home && python3 get_audio_streamed.py'
    ])

def start_file_client():
    subprocess.run([
        'docker', 'exec', '-it', 'file_client',
        'bash', '-c', 'cd /home && python3 file_transfer_client.py'
    ])

def start_web_client():
    subprocess.run([
        'docker', 'exec', '-it', 'web_client',
        'bash', '-c', 'cd /home && python3 web_client.py'
    ])

# ------------------------------
# iPerf flow functions
# ------------------------------
def start_iperf_server(host, port):
    host.cmd(f'iperf -s -p {port} -u &')

def start_iperf_client(host, target_ip, port, bandwidth='5M', duration=1800):
    host.cmd(f'iperf -c {target_ip} -p {port} -u -b {bandwidth} -t {duration} &')

# Function to stop iPerf on a host
def stop_iperf(host):
    host.cmd('pkill iperf')

# Function to change link properties (bottleneck link)
def change_link_properties(link, bw, delay, jitter=0, loss=0):
    info(f'*** Changing link properties: BW={bw} Mbps, Delay={delay} ms, Jitter={jitter} ms, Loss={loss}%\n')
    link.intf1.config(bw=bw, delay=f'{delay}ms', jitter=f'{jitter}ms', loss=loss)
    link.intf2.config(bw=bw, delay=f'{delay}ms', jitter=f'{jitter}ms', loss=loss)

if __name__ == '__main__':
    # ------------------------------
    # Parsing command-line arguments
    # ------------------------------
    parser = argparse.ArgumentParser(description='Multi-service network testbed.')
    parser.add_argument('--autotest', dest='autotest', action='store_const',
                        const=True, default=False,
                        help='Enable automatic testing and close services automatically.')
    parser.add_argument('--services', type=str, default='video,audio,file,web',
                        help='Comma-separated list of services to run (video,audio,file,web)')
    args = parser.parse_args()
    autotest = args.autotest
    services_to_run = args.services.split(',')

    # ------------------------------
    # Setting-up environment + network
    # ------------------------------
    script_directory = os.path.abspath(os.path.dirname(__file__))
    shared_directory = os.path.join(script_directory, 'pcap')
    if not os.path.exists(shared_directory):
        os.makedirs(shared_directory)

    setLogLevel('info')

    net = Containernet(controller=Controller, link=TCLink, xterms=False)
    mgr = VNFManager(net)

    info('*** Adding controller\n')
    net.addController('c0')

    info('*** Creating switches\n')
    # Create a more complex topology with 4 switches in a diamond pattern
    s1 = net.addSwitch('s1')  # Edge switch 1
    s2 = net.addSwitch('s2')  # Core switch 1
    s3 = net.addSwitch('s3')  # Core switch 2
    s4 = net.addSwitch('s4')  # Edge switch 2

    info('*** Creating service hosts\n')
    # Video streaming hosts
    video_server_host = net.addDockerHost(
        'video_server_host', dimage='dev_test', ip='10.0.0.10',
        docker_args={'hostname': 'video_server_host'}
    )
    video_client_host = net.addDockerHost(
        'video_client_host', dimage='dev_test', ip='10.0.0.11',
        docker_args={'hostname': 'video_client_host'}
    )
    
    # Audio streaming hosts
    audio_server_host = net.addDockerHost(
        'audio_server_host', dimage='dev_test', ip='10.0.0.20',
        docker_args={'hostname': 'audio_server_host'}
    )
    audio_client_host = net.addDockerHost(
        'audio_client_host', dimage='dev_test', ip='10.0.0.21',
        docker_args={'hostname': 'audio_client_host'}
    )
    
    # File transfer hosts
    file_server_host = net.addDockerHost(
        'file_server_host', dimage='dev_test', ip='10.0.0.50',
        docker_args={'hostname': 'file_server_host'}
    )
    file_client_host = net.addDockerHost(
        'file_client_host', dimage='dev_test', ip='10.0.0.51',
        docker_args={'hostname': 'file_client_host'}
    )
    
    # Web service hosts
    web_server_host = net.addDockerHost(
        'web_server_host', dimage='dev_test', ip='10.0.0.60',
        docker_args={'hostname': 'web_server_host'}
    )
    web_client_host = net.addDockerHost(
        'web_client_host', dimage='dev_test', ip='10.0.0.61',
        docker_args={'hostname': 'web_client_host'}
    )

    # iPerf hosts (only one pair)
    iperf_server = net.addHost('h1', ip='10.0.0.101')
    iperf_client = net.addHost('h2', ip='10.0.0.102')

    info('*** Adding links\n')
    # Core network links (with potential bottlenecks)
    core_link1 = net.addLink(s1, s2, bw=100, delay='5ms')
    core_link2 = net.addLink(s2, s3, bw=50, delay='10ms')  # This will be our main bottleneck
    core_link3 = net.addLink(s3, s4, bw=100, delay='5ms')
    net.addLink(s1, s3, bw=75, delay='8ms')  # Alternative path
    net.addLink(s2, s4, bw=75, delay='8ms')  # Alternative path

    # Connect service hosts to edge switches
    # Server-side hosts connect to s1
    net.addLink(s1, video_server_host)
    net.addLink(s1, audio_server_host)
    net.addLink(s1, file_server_host)
    net.addLink(s1, web_server_host)
    
    # Client-side hosts connect to s4
    net.addLink(s4, video_client_host)
    net.addLink(s4, audio_client_host)
    net.addLink(s4, file_client_host)
    net.addLink(s4, web_client_host)
    
    # Connect iPerf hosts
    net.addLink(s1, iperf_server)   # Server to s1
    net.addLink(s4, iperf_client)   # Client to s4

    info('\n*** Starting network\n')
    net.start()

    # Quick connectivity check between hosts
    info("*** Testing connectivity between hosts\n")
    reply = video_client_host.cmd("ping -c 3 10.0.0.10")
    print(reply)

    # Setting link properties for the bottleneck link
    change_link_properties(core_link2, 40, 15, 5, 0.2)

    # ------------------------------
    # Starting TCPDump captures
    # ------------------------------
    capture_interface = core_link2.intf1.name  # Capture on the bottleneck link
    
    # Create separate captures for each service and iPerf flows
    tcpdump_processes = []
    
    # Setup captures for each service
    service_ports = {
        "video": 8000,
        "audio": 8001,
        "file": 8004,
        "web": 8080
    }
    
    # Setup captures for each active service
    for service in services_to_run:
        if service in service_ports:
            port = service_ports[service]
            capture_file = os.path.join(shared_directory, f"{service}_traffic.pcap")
            tcpdump_cmd = [
                "sudo", "tcpdump", "-i", capture_interface, "-s", "96",
                f"port {port}", "-w", capture_file
            ]
            info(f'*** Starting tcpdump for {service} service -> {capture_file}\n')
            tcpdump_proc = subprocess.Popen(tcpdump_cmd)
            tcpdump_processes.append(tcpdump_proc)
    
    # Setup capture for iPerf traffic (only one flow on port 5001)
    iperf_capture = os.path.join(shared_directory, "iperf_flow.pcap")
    tcpdump_cmd = [
        "sudo", "tcpdump", "-i", capture_interface, "-s", "96",
        "udp port 5001", "-w", iperf_capture
    ]
    info(f'*** Starting tcpdump for iPerf Flow -> {iperf_capture}\n')
    tcpdump_proc = subprocess.Popen(tcpdump_cmd)
    tcpdump_processes.append(tcpdump_proc)
    
    # Capture all other traffic
    other_capture = os.path.join(shared_directory, "other_traffic.pcap")
    tcpdump_cmd = [
        "sudo", "tcpdump", "-i", capture_interface, "-s", "96",
        "not (port 8000 or port 8001 or port 8004 or port 8080 or udp port 5001)",
        "-w", other_capture
    ]
    info(f'*** Starting tcpdump for other traffic -> {other_capture}\n')
    tcpdump_proc = subprocess.Popen(tcpdump_cmd)
    tcpdump_processes.append(tcpdump_proc)

    # ------------------------------
    # Adding service containers
    # ------------------------------
    service_containers = {}
    
    if 'video' in services_to_run:
        service_containers['video_server'] = add_service_container(mgr, 'video_server', 'video_server_host', 'video_server_image', shared_directory)
        service_containers['video_client'] = add_service_container(mgr, 'video_client', 'video_client_host', 'video_client_image', shared_directory)
    
    if 'audio' in services_to_run:
        service_containers['audio_server'] = add_service_container(mgr, 'audio_server', 'audio_server_host', 'audio_server_image', shared_directory)
        service_containers['audio_client'] = add_service_container(mgr, 'audio_client', 'audio_client_host', 'audio_client_image', shared_directory)
    
    if 'file' in services_to_run:
        service_containers['file_server'] = add_service_container(mgr, 'file_server', 'file_server_host', 'file_server_image', shared_directory)
        service_containers['file_client'] = add_service_container(mgr, 'file_client', 'file_client_host', 'file_client_image', shared_directory)
    
    if 'web' in services_to_run:
        service_containers['web_server'] = add_service_container(mgr, 'web_server', 'web_server_host', 'web_server_image', shared_directory)
        service_containers['web_client'] = add_service_container(mgr, 'web_client', 'web_client_host', 'web_client_image', shared_directory)

    # ------------------------------
    # Starting service threads
    # ------------------------------
    service_threads = []
    
    if 'video' in services_to_run:
        video_server_thread = threading.Thread(target=start_video_server)
        video_client_thread = threading.Thread(target=start_video_client)
        service_threads.extend([video_server_thread, video_client_thread])
        video_server_thread.start()
        video_client_thread.start()
    
    if 'audio' in services_to_run:
        audio_server_thread = threading.Thread(target=start_audio_server)
        audio_client_thread = threading.Thread(target=start_audio_client)
        service_threads.extend([audio_server_thread, audio_client_thread])
        audio_server_thread.start()
        audio_client_thread.start()
    
    if 'file' in services_to_run:
        file_server_thread = threading.Thread(target=start_file_server)
        file_client_thread = threading.Thread(target=start_file_client)
        service_threads.extend([file_server_thread, file_client_thread])
        file_server_thread.start()
        file_client_thread.start()
        
    if 'web' in services_to_run:
        web_server_thread = threading.Thread(target=start_web_server)
        web_client_thread = threading.Thread(target=start_web_client)
        service_threads.extend([web_server_thread, web_client_thread])
        web_server_thread.start()
        web_client_thread.start()

    # ------------------------------
    # Starting iPerf flow
    # ------------------------------
    def iperf_control():
        info('*** Starting iPerf flow (30mins duration)...\n')
        
        # Start iPerf server
        start_iperf_server(iperf_server, 5001)
        
        # Start iPerf client
        start_iperf_client(iperf_client, iperf_server.IP(), 5001, '5M')
        
        # Run for 30 minutes
        time.sleep(1800)
        
        info('*** Stopping iPerf flow...\n')
        stop_iperf(iperf_server)
        stop_iperf(iperf_client)

    iperf_thread = threading.Thread(target=iperf_control)
    iperf_thread.start()

    # ------------------------------
    # Waiting for service threads to finish
    # ------------------------------
    for thread in service_threads:
        thread.join()

    # Wait for iPerf thread to finish (after 30mins)
    iperf_thread.join()

    if not autotest:
        CLI(net)

    # ------------------------------
    # Terminating tcpdump captures
    # ------------------------------
    info('*** Terminating tcpdump captures\n')
    for proc in tcpdump_processes:
        proc.terminate()
        proc.wait()

    # ------------------------------
    # Cleanup
    # ------------------------------
    for container_name in service_containers:
        mgr.removeContainer(container_name)
    
    net.stop()
    mgr.stop()
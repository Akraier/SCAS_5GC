import pyshark
import argparse
import os
import signal
import multiprocessing
import subprocess

def capture_packets(interface):
    # waiting interface is up
    while True:
        try:
            result = subprocess.run(
                ["ip", "link", "show", interface], capture_output=True, text=True
            ).stdout
            if "UP" in result:
                print("[+]Start Sniffing...")
                break
        except Exception as e:
            print("[!]Error checking interface")
            exit()
    print("[+] Sniffing for packets...", flush=True)
    # Start live capture on the interface
    try:
        capture = pyshark.LiveCapture(interface=interface, display_filter='sctp')

        # Iterate through the captured packets
        for packet in capture.sniff_continuously():
            print(f"Packet captured: {packet}")
            if hasattr(packet, 'sctp'):
                print(f"SCTP Stream: {packet.sctp.stream}")
                print(f"Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}")

                """ # Check if the packet is a heartbeat
                if hasattr(packet.sctp, 'heartbeat_info'):
                    print(f"Heartbeat info: {packet.sctp.heartbeat_info}") """
    except Exception as e:
        print("Error capturing packets:", e)
                
def start_free5gc(path):
    try:
        if os.path.exists(path):
            os.system("docker compose -f {} up -d >/dev/null 2>&1".format(path))
            print("[+]Free5GC started")
        else:
            print("[!]Invalid path")
    except Exception as e:
        print("Error starting Free5GC:", e, flush=True)

#Signal handler for graceful docker compose shutdown
def graceful_shutdown(signal, frame):
    #Function to handle cleanup and shutdown gracefully
    print(f"\nGracefully shutting down... Signal: {signal}")
    os.system("docker compose -f {} down >/dev/null 2>&1".format(free5g_path))
    print("[-]Docker Compose shutdown completed.")
    exit(0)

signal.signal(signal.SIGINT, graceful_shutdown) 

if __name__ == "__main__":
    argparse = argparse.ArgumentParser(description="SCAS_AMF")
    argparse.add_argument("-i", "--interface", dest="interface", help="Interface to sniff on", required=True, type=str)
    argparse.add_argument("-p", "--path", dest="free5gc_path", help="Absolute path to Free5GC", required=True, type=str)
    _args = argparse.parse_args()
    free5g_path = _args.free5gc_path

    free5gc = multiprocessing.Process(target=start_free5gc, args=(_args.free5gc_path,))
    sniffing_process = multiprocessing.Process(target=capture_packets, args=(_args.interface,))
    free5gc.start()
    sniffing_process.start()

    
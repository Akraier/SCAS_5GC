import multiprocessing
import subprocess
import signal
import time
import json
import threading
import logging
import argparse
import traceback
import os
from MyNGAPdissector import *
from scapy.all import sniff, wrpcap, Ether, SCTPChunkData

SEC_MODE_COMPLETE = 0x5E  # NAS message type
pkt_counter = 0


def packet_processing(pkt):
    global pkt_counter
    try:
        if pkt.haslayer(SCTPChunkData):
            chunk = pkt[SCTPChunkData]
            #print(f"Chunk proto_id: {chunk.proto_id}")
            chunk_data = chunk.data  # Extract SCTP Data chunk payload

            #data length check
            if len(chunk_data) == 0:
                    print("[-] Empty chunk data")
                    return
            print(f"[DEBUG] Chunk Data Length: {len(chunk_data)}")
            #print(f"[DEBUG] Modulo 4 Check: {len(chunk_data) % 4}")
            #NGAP PDU has proto_id 60
            if chunk.proto_id == 60:
            # If it's not aligned, manually pad it
                if len(chunk_data) % 4 != 0:
                    padding_needed = 4 - (len(chunk_data) % 4)
                    chunk_data += b'\x00' * padding_needed  # Manually add padding
                    print(f"[DEBUG] Padded Data Length: {len(chunk_data)}")
                # Ensure chunk.data is passed correctly
                
                # Debug first byte
                first_byte = chunk.data[0]
                #print(f"[DEBUG] Raw First byte: {hex(first_byte)}")
                #print(f"[DEBUG] Bin First byte: {bin(first_byte)}")
                #print(f"[DEBUG] Extract pdu_type: {first_byte >> 4}")
                print(f"[DEBUG] Raw chunk data (first 10 bytes): {chunk.data[:10].hex()}")
            
                #parse NGAP PDU
                """ ngap_pdu = NGAPPDU(chunk_data)
                print(f"[+] NGAP PDU: \n{ngap_pdu.show(dump=True)}")
                print(f"[+] NGAP PDU Type: {ngap_pdu.pdu_type}")
                print(f"[+] NGAP PDU Value: {ngap_pdu.value}") """
                pkt_counter += 1
                print(f"[+] Processing NGAP packet #{pkt_counter}")
                dissect_ngap_pdu(chunk_data)
    except Exception as e:
        print("[!]Error processing packet:", e)
        print("[!]Exception type:", type(e).__name__)
        print("[!] Full Traceback:")
        traceback.print_exc()
        return
    

def start_free5gc():
    print("[*] Starting Free5GC network...", flush=True)
    try:
        os.system("docker compose -f /home/vincenzo_d/free5gc-compose/docker-compose.yaml up -d")
        #subprocess.run(["docker","compose","-f","/home/vincenzo_d/free5gc-compose/docker-compose.yaml", "up", "-d"], check=True)
        print(f"[+][{time.time()}]Free5GC started")
    except Exception as e:
        print("Error starting Free5GC:", e, flush=True)

def sniff_packets(dump):
    # waiting interface
    while True:
        try:
            result = subprocess.run(
                ["ip", "link", "show", "br-free5gc"], capture_output=True, text=True
            ).stdout
            if "UP" in result:
                print(f"[+][{time.time()}]Start Sniffing...")
                break
        except Exception as e:
            print("[!]Error checking interface: ", e)
            continue

    print("[*]Sniffing for packets...", flush=True)
    """ if dump == "y":
        print("[*]Dumping pkts...")
        packets = sniff(iface="br-free5gc",
                        filter="sctp port 38412",
                        prn=lambda pkt: pkt.show(),
                        #lfilter=lambda p: p.haslayer(SCTP)
                        )
        wrpcap("pkt_dump.pcap", packets) """
    if dump == "n":
        packets = sniff(iface="br-free5gc",
                        filter="sctp port 38412",
                        prn=packet_processing,
                        store=False)
        

def graceful_shutdown(signal, frame):
    #Function to handle cleanup and shutdown gracefully
    print(f"\nGracefully shutting down... Signal: {signal}")
    subprocess.run(["docker", "compose", "-f", "/home/vincenzo_d/free5gc-compose/docker-compose.yaml", "down"], check=True)
    print("Docker Compose shutdown completed.")
    exit(0)

signal.signal(signal.SIGINT, graceful_shutdown) 
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGABRT, graceful_shutdown) 

if __name__ == "__main__":
    """ argparser = argparse.ArgumentParser(description="Free5GC Network Sniffer")
    argparser.add_argument("--dump",type=str, dest="dump", help="Save sniffed traffic to a pcap file", default="n")
    arg=argparser.parse_args() """
    # Start Free5GC containers.
    free5gc_thread = multiprocessing.Process(target=start_free5gc)
    interface_thread = multiprocessing.Process(target=sniff_packets, args=("n"))
    free5gc_thread.start()
    interface_thread.start()
    
    free5gc_thread.join()
    interface_thread.join()
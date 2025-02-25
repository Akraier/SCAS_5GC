import socket 
import os
import argparse
import multiprocessing
import subprocess
import signal
from sctp import *


#Known patterns
AMF_N1_PORT = b'\x96\x0c'   #AMF NAS port 38412 in SCTP header
NAS_EPD_SecHeader = b'\x7e\x00'   #NAS EPD and Security Header
id_NAS_PDU_Criticality = b'\x00\x26\x00'    #Nas PDU id and criticality 
SCTP_protocol_id = b'\x84'   #SCTP protocol id
SEC_MODE_COMPLETE = 0x5e    #Message type for Security Mode Complete
NGAP_proto_id = b'\x00\x00\x00\x3c'    #NGAP protocol id

free5g_path = ""

def process_pkt(pkt):
    #print("[+]Processing packet\n>>{}".format(pkt.hex()))
    print("Comparing pkt[23:24] {} == {} SCTP_protocol_id".format(pkt[23:24], SCTP_protocol_id))
    if pkt[23:24] == SCTP_protocol_id:
        print("[+]SCTP packet detected")
        print("pkt = {}".format(pkt))
        SCTP_segment = SCTP(pkt)
        SCTP_segment.print_SCTP()
        for chunk in SCTP_segment.chunks:
            chunk.print_SCTP_chunk()
            if chunk.identify_chunk() == "SCTPChunkData":
                print("[+]SCTPChunkData found")
                #filter_NGAP(chunk)

def process_queue(queue_in, queue_out, pkt_counter):
    try:
        pkt = queue_in.get()
        queue_out.put(pkt)
        print(f"[+]Packet #{pkt_counter}")
        process_pkt(pkt)
    except Exception as e:
        print("[!]Error processing queue:", e)
        return

def sniff(interface):
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

    #Creating raw socket for sniffing any packet on the interface
    global raw_socket 
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)  # Large buffer
    #raw_socket.setblocking(False)  # Non-blocking mode
    raw_socket.bind((interface, 0x0003))

    #Creating queues to store packets and avoid received packets not processed
    """ _pkt_queue = multiprocessing.SimpleQueue()
    pkt_queue_ = multiprocessing.SimpleQueue() """
    pkt_counter = 0

    while True:
        try:
            pkt_counter += 1
            packet = raw_socket.recvfrom(65535)[0]
            print(f"[+]Packet captured:\n>>{packet[23:24]}")
            process_pkt(packet)
            #print(f"[+]Packet captured:\n>>{packet.hex()}")
            """ _pkt_queue.put(packet)
            p = multiprocessing.Process(target=process_queue, args=(_pkt_queue, pkt_queue_,pkt_counter)).start()
            p.daemon = True """
        except Exception as e:
            print("[!]Error sniffing packets:", e)


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
    if raw_socket:
        raw_socket.close
        print("[-]Raw socket closed")
    exit(0)

signal.signal(signal.SIGINT, graceful_shutdown) 
#signal.signal(signal.SIGTERM, graceful_shutdown)
#signal.signal(signal.SIGABRT, graceful_shutdown) 

if __name__ == "__main__":
    argparse = argparse.ArgumentParser(description="SCAS_AMF")
    argparse.add_argument("-i", "--interface", dest="interface", help="Interface to sniff on", required=True, type=str)
    argparse.add_argument("-p", "--path", dest="free5gc_path", help="Absolute path to Free5GC", required=True, type=str)
    _args = argparse.parse_args()
    free5g_path = _args.free5gc_path

    #declaring processes
    free5gc = multiprocessing.Process(target=start_free5gc, args=(_args.free5gc_path,))
    sniffing_process = multiprocessing.Process(target=sniff, args=(_args.interface,))
    free5gc.start()
    sniffing_process.start()

import multiprocessing
import subprocess
import signal
import time
import json
import threading
import logging
import argparse
import traceback
import queue
import os
from MyNGAPdissector import *
#from MyTest import *
from scapy.all import sniff, PcapWriter, Ether, SCTPChunkData

SEC_MODE_COMPLETE = 0x5E  # NAS message type
pkt_counter = 0


tests = {
    -1: {
        "name": "ANY",
        "group": "ANY",
        "NFs": "ANY"
    },
    0: {
        "name": "TC_AMF_NAS_INTEGRITY_FAILURE",
        "group": "NGAP/NAS",
        "NFs": "AMF"
    }
}

def ueransim_ue_interaction(command):
    #Function to interact with UERANSIM UE shell
    #command: command to be executed
    #return: output of the command
    retrieve_UEs = """./nr-cli -d"""    #retrieve available UEs
    if command not in {"info","status","timers","coverage","ps-establish","ps-list","ps-release","ps-release-all","deregister"}:
        #ensure asking for a valid command
        print("[!]Invalid command")
        return None
    try:
        #retrieve available UEs
        output = subprocess.run(["docker", "exec", "-it", "ue", "/bin/sh", "-c", retrieve_UEs], capture_output=True, text=True)
        #print("captured output(imsi):"+output.stdout)
        imsi = output.stdout.strip()    #remove /n from the output to avoid breaking shell   
        #print("imsi:"+imsi)
        run_command = f"""./nr-cli {imsi} --exec {command}"""   
        #print("run_command:"+run_command)
        output = subprocess.run(["docker", "exec", "-it", "ue", "/bin/sh", "-c", run_command], capture_output=True, text=True)
        #run the required command
        return output.stdout
    except Exception as e:
        print("[!]Error interacting with UERANSIM UE shell: ", e)
        return None

    
def tc_amf_nas_integrity_failure( q, q_bkup ):
    #TBD WAIT FOR UERANSIM TO BE READY

    #Test case: TC_AMF_NAS_INTEGRITY_FAILURE
    #In case faulty or missing NAS-MAC after NAS integrity protection start
    #concerned msg should be discarded - except for specific msgs TS 24.501 5.3.20
    #Test case 1 (wrong NAS-MAC):
    #1. The tester triggers the UE to initiate an initial registration procedure with the AMF. OK, at this point UE is registerd
    #Should ensure this? open UE shell and check registration status
    ue_status = ueransim_ue_interaction("status")
    if "MM-REGISTERED" not in ue_status or "RM-REGISTERED" not in ue_status:
        #no real need to check since Reg Req is sent automatically by UERANSIM after deregistration
        #no know way to manually trigger Reg Req
        #So if in this case, a blocking error probably occurred with UERANSIM 
        #conservative approach kill free5gc and exit
        print("[!]UE not registered")
        graceful_shutdown(signal.SIGTERM, None)
        
    #2. The AMF sends the Security Mode Complete message to the UE.
    #scan q looking for Security Mode Complete message

    #create backup queue
    smc_fnd = False
    while not queue.empty():
        ngap_segment = q.get()
        q_bkup.put(ngap_segment)
        nas_pdu = ngap_segment.get_nas_pdu()
        if nas_pdu["epd"] == "Mobility Management Message"\
              and nas_pdu["sht"] == "Integrity + Encryption by 5GNAS Security Context"\
              and SEC_MODE_COMPLETE in nas_pdu["end_msg"] :
            print("[+] Security Mode Complete message found")
            smc_fnd = True
            break
    #3. After the Security Mode Complete message, send a NAS message from the UE to the AMF with a wrong NAS-MAC. 
    # The message used must not be an exception in TS 24.501 [5].
    #grub a NAS message from the queue from which AMF reaction is expected
    if smc_fnd:
        #send tampered mac deregistration request
        #ensure no deregistration response is received
        try:
            with open("hex_dereg_req.json") as f:
                data = json.load(f)
                segment = NGAP(bytes.fromhex(data["ngap"]))
                print("Injecting DEREGISTRATION REQUEST with wrong NAS-MAC")
                 
            print("SEGMENT OK")
        except Exception as e:
            print("[!]Error extracting deregistration request: ")
            traceback.print_exc()
            return None

def n1n2_packet_processing(pkt, test, q):
    global pkt_counter
    try:
        if pkt.haslayer(SCTPChunkData):
            chunk = pkt[SCTPChunkData]
            chunk_data = chunk.data  # Extract SCTP Data chunk payload

            #data length check
            if len(chunk_data) == 0:
                    print("[-] Empty chunk data")
                    return
            
            if chunk.proto_id == 60:
                #NGAP PDU has proto_id 60
                if len(chunk_data) % 4 != 0:
                    # If it's not aligned, manually pad it
                    padding_needed = 4 - (len(chunk_data) % 4)
                    chunk_data += b'\x00' * padding_needed  # Manually add padding
                    #print(f"[DEBUG] Padded Data Length: {len(chunk_data)}")
                
                pkt_counter += 1
                print(f"[+] Processing NGAP packet #{pkt_counter}")
                ngap = NGAP()
                if ngap.dissect_ngap_pdu(chunk_data):
                    ngap.print_ngap()
                #q.put(ngap.segment)
                
    except Exception as e:
        print("[!]Error processing packet:", e)
        print("[!]Exception type:", type(e).__name__)
        print("[!] Full Traceback:")
        traceback.print_exc()
        return
    

def start_free5gc():
    try:
        os.system("docker compose -f /home/vincenzo_d/free5gc-compose/docker-compose.yaml up -d >/dev/null 2>&1")
    except Exception as e:
        print("Error starting Free5GC:", e, flush=True)

def sniff_packets(dump,test,q):
    # waiting interface
    while True:
        try:
            result = subprocess.run(
                ["ip", "link", "show", "br-free5gc"], capture_output=True, text=True
            ).stdout
            if "UP" in result:
                break
        except Exception as e:
            print("[!]Error checking interface: ", e)
            continue
    
    print("[*]Sniffing for packets...", flush=True)
    
    #TBD: Packet class is needed?
    #Test cases selected by protocol(s)
    if tests[test]["group"] == "NGAP/NAS":
        #n1n2 interface sniffing
        packets = sniff(iface="br-free5gc",
                        filter="sctp port 38412",
                        prn=lambda packet: n1n2_packet_processing(packet, test, q),
                        store=False)
    
        
        

def graceful_shutdown(signal, frame):
    #Function to handle cleanup and shutdown gracefully
    #When multi-process a signal is caught by every process and this function is called multiple times. Watch out>>>Find a method to fix the behavior
    print(f"\nGracefully shutting down... Signal: {signal}")
    subprocess.run(["docker", "compose", "-f", "/home/vincenzo_d/free5gc-compose/docker-compose.yaml", "down"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Docker Compose shutdown completed.")
    exit(0)

signal.signal(signal.SIGINT, graceful_shutdown) 
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGABRT, graceful_shutdown) 

if __name__ == "__main__":
    # Parse arguments
    argparser = argparse.ArgumentParser(description="Free5GC Network Sniffer")
    argparser.add_argument("--dump",type=str, dest="dump", help="Save sniffed traffic to a pcap file", default="n")
    argparser.add_argument("--test",type=int, dest="test", help="Select test case, default 'ANY' . --tests-enum lists available tests", default=-1)
    argparser.add_argument("--test-enum", action="store_true", help="Show every test available")
    arg = argparser.parse_args()

    #queue
    q = multiprocessing.Queue()
    q_bkup = multiprocessing.Queue()    #backup queue avoids losing older packets, possibly empty once -if always- the core is restarted

    #test = myTestCase(arg.test)
    if arg.test_enum:
        tests = json.dumps(tests,indent=4)
        print(tests)
        exit(0)

    if arg.test not in tests.keys():
        print("[!] Selected test not available")
        argparser.print_help()
        exit(0)

    # Start Free5GC containers.
    free5gc_thread = multiprocessing.Process(target=start_free5gc)
    interface_thread = multiprocessing.Process(target=sniff_packets, args=(arg.dump,arg.test,q,))
    print(f"[+][{time.strftime('%Y%m%d_%H:%M:%S')}] Starting Free5GC")
    free5gc_thread.start()
    interface_thread.start()

    """ if tests[arg.test]["name"] == "TC_AMF_NAS_INTEGRITY_FAILURE":
        print(f"[+] Test case: {tests[arg.test]['name']} selected")
        test_nas_integrity_failure = multiprocessing.Process(target=tc_amf_nas_integrity_failure, args=(q,q_bkup,))
        test_nas_integrity_failure.start()
        test_nas_integrity_failure.join() """
        
    
    
    
    free5gc_thread.join()
    interface_thread.join()

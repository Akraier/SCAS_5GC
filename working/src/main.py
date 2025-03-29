import multiprocessing
import subprocess
import signal
import time
import json
import sctp
import socket
import logging
import argparse
import traceback
import queue
import os
from MyNGAPdissector import *
#from MyTest import *
from scapy.all import sniff, PcapWriter, Ether, SCTPChunkData, SCTP, IP

SEC_MODE_COMPLETE = 0x5E  # NAS message type
pkt_counter = 0

Qmanager = DynamicMultiQueueManager(["qpkt"])

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

"""
Function that retrieves container's ip 
"""

def container_ip(container):
    output = subprocess.run(
        ["docker", "inspect", "-f", "'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'", container], 
        capture_output=True, 
        text=True)
    if output.returncode != 0:
        print("[!]Error retrieving IP")
        return None
    ip = output.stdout.strip()
    ip = ip.strip("'")
    return ip

"""
Function that interact with UERANSIM UE shell running nr-cli commands
Useful for status retrieval or other interaction needed with the ue
"""

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

"""
Analayze SCTP messages between UE and AMF

Returns sctp source and dest ports plus the vtag for the direction selected

"""

def analyze_sctp(pkt, src_ip, dst_ip):
    

    if not pkt.haslayer(SCTP):
        return False
    ip_layer = pkt[IP]
    sctp_layer = pkt[SCTP]

    
    if ip_layer.src == src_ip and ip_layer.dst == dst_ip:
        
        #Correct direction needed
        flow = {
            "sctp_src_port":sctp_layer.sport,
            "sctp_dst_port":sctp_layer.dport,
            "vtag": sctp_layer.verification_tag
        }
        return flow
    else:
        return False

"""
Create sctp association and send message
"""

def sctp_send(ip, port, raw_message):
    
    sctp_socket = sctp.sctpsocket_tcp(socket.AF_INET)

    sctp_socket.bind(('0.0.0.0', 5000))

    print(f"[+]Connection to AMF at {ip}:{port}")
    sctp_socket.connect((ip,port))

    sctp_socket.send(raw_message)
    print(f"[+]SCTP message sent!")

    sctp_socket.close()


def dereg_resp_find(pipe):
    print("[+] Looking for Deregistration Accept")
    """
    Listen 10s(ARBITRARILY) looking for deregistration response
    """
    start = time.time()
    while time.time() - start < 10:
        try:
            pkt = Qmanager.get('qpkt')
            if pkt.haslayer(SCTPChunkData) and pkt[SCTPChunkData].proto_id == 60:
                #NGAP found
                ngap = NGAP()
                ngap.dissect_ngap_pdu(pkt[SCTPChunkData].data)
                nas = ngap.get_nas_pdu()
                if nas is None:
                    continue
                elif "Deregistration accept" in nas["PlainNASPDU"]["message_type"] :
                    pipe.send(False)
                    return 
            else:
                continue
        except Exception as e:
            traceback.print_exc()
            print(f"[!] Error looking for DEREGISTRATION ACCEPT: {e}")
            continue
    pipe.send(True)
    return 

"""
Test case: TC_AMF_NAS_INTEGRITY_FAILURE

In case faulty or missing NAS-MAC after NAS integrity protection start
concerned msg should be discarded - except for specific msgs TS 24.501 5.3.20
Test case 1 (wrong NAS-MAC):
1. The tester triggers the UE to initiate an initial registration procedure with the AMF. 
2. The AMF sends the Security Mode Complete message to the UE.
3. After the Security Mode Complete message, send a NAS message from the UE to the AMF with a wrong NAS-MAC. 
   The message used must not be an exception in TS 24.501 [5].

Attention points:
- SCTP association with AMF 
    a. Expose AMF container's SCTP port to host (SELECTED APPROACH)
    b. create ad-hoc container to run the test
- Select a message to 'replay' or send that should take tangible effect into AMF. 
    SELECTED APPROACH: 
        Craft and send Deregistration message with tampered integrity value, possibly 0xffffffff
        
"""
def tc_amf_nas_integrity_failure():
    print("[+] amf_nas_integrity test case STARTED")

    
    while True:
        ue_status = ueransim_ue_interaction("status")
        if "MM-REGISTERED" not in ue_status or "RM-REGISTERED" not in ue_status:
            """ 
            Sync with ue waiting for registration  
            """
            print("[!]UE not yet Registered")
            #print(ue_status)
            time.sleep(2)
            continue
        else:
            print("[+]UE Registered")
            break
        
    """ 
    2. The AMF sends the Security Mode Complete message to the UE.
    scan q looking for Security Mode Complete message 
    """

    """
    qngap queue should have been created by sniff process at this point, in case not, wait for
    """
    
    while Qmanager.empty('qpkt'):
        time.sleep(1)
    #Qmanager.add_queue('qngap') #needed?
    #Qmanager.add_queue('qbkup')
    ngap = NGAP()
    nas_pdu = {}
    while True:

        pkt = Qmanager.get('qpkt')
        if pkt.haslayer(SCTPChunkData) and pkt[SCTPChunkData].proto_id == 60:
            
            ngap.dissect_ngap_pdu(pkt[SCTPChunkData].data)
            nas_pdu = ngap.get_nas_pdu() 
            if nas_pdu is None:
                #NO NAS PDU
                continue
        else:
            #NO NGAP PDU
            continue
        """
        Look for Security Mode Complete message
        """
        if nas_pdu["PlainNASPDU"]["message_type"] == "Security mode complete":
            print("[+] Security Mode Complete message found")
            break
        else:
            continue
            
    """ 
    3. After the Security Mode Complete message, send a NAS message from the UE to the AMF with a wrong NAS-MAC. 
    The message used must not be an exception in TS 24.501 [5].
    grub a NAS message from the queue from which AMF reaction is expected 
    """
    
    #send tampered mac deregistration request
    #ensure no deregistration response is received
    try:
        """
        Read deregistration request sample previously sniffed
        .json format ->
        {
            "raw": //full dereg request Eth to NAS
            "NGAP": ..
            "NAS": .. 
        }
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_dir, "../data/hex_dereg_req.json")
        """ 
        hex_dereg_req.json is extracted from the particular free5gc instance 
        I'm using in this study. For other instances, consider regenerate the
        file to better fit your environment.  
        """
        with open(file_path) as f:
            data = json.load(f)

        ngap = NGAP()
        """Using dissected json for easier modification of target fields """
        ngap.dissect_ngap_pdu(bytes.fromhex(data["ngap"]))
        print("[+]Injecting DEREGISTRATION REQUEST with wrong NAS-MAC")
        
        print("[+]Untampered Deregistration Retrieved")
        #ngap.print_ngap()   #In case any further clearence is needed
        mac = ngap.segment["Initiating Message"]["IEs"]["id-NAS-PDU"]["NAS PDU"]["SecurityProtectedNASPDU"]["mac"]
        mac_bytes = bytes.fromhex(mac)
        mac_bytes = b'\xff\xff\xff\xff'  #overwrite mac
        mac = mac_bytes.hex()
        print(f"[+] --> Tampered MAC with 0xff: {mac}")
        ngap.segment["Initiating Message"]["IEs"]["id-NAS-PDU"]["NAS PDU"]["SecurityProtectedNASPDU"]["mac"] = mac
        print("[+]Tampered Deregistration Crafted")
        #ngap.print_ngap()

        """ 
        Compose tampered packet
        Components needed 
        - AMF/gNB IPs
        - SCTP source and dest ports
        - SCTP tags --> This is highly dependent on SCTP session and it is strongly needed to intercept UE-AMF SCTP session tag
        - SCTP stream identifier [ChunkData]
        - SCTP stream sequence number

        OR IT'S BETTER TO BUILD A BRAND NEW SCTP CONNECTION?
        AMF considers any sctp connection as coming from a gNB, sctp is not authenticated indeed
        """ 

        amf_ip = container_ip('amf')
        #gnb_ip = container_ip('ueransim')   #NAS is actually enforced by gnb working as proxy for ue
        raw_ngap = ngap.build_ngap_pdu(ngap.segment)
        sctp_send(amf_ip,38412,raw_ngap)

        """ while True:
            
            #Looking for sctp data from the actual co
            
            pkt = Qmanager.get('qpkt')
            sctp_data = analyze_sctp(pkt,gnb_ip,amf_ip)
            if sctp_data is False:
                continue
            else:
                print("[-]Found SCTP Data")
                break """

        """
        Evaluate test result.
        AMF DISCARD NAS MESSAGE
        --> BEST option, look for DEREGISTRATION RESPONSE FOR A CERTAIN AMOUNT OF TIME
            IF NONE, TEST PASS. IF ANY TAST FAILS
        """    
        parent_pipe, child_pipe = multiprocessing.Pipe()    #Pipe to send finding result from subprocess
        dereg_resp_finder = multiprocessing.Process(target = dereg_resp_find, args=(child_pipe,)) 
        dereg_resp_finder.start()

        result = parent_pipe.recv()
        
        dereg_resp_finder.join()
        if result:
            print("[+] AMF NAS INTEGRITY Test Case: PASSED")
             
            return True
        else:
            print("[+] AMF NAS INTEGRITY Test Case: FAILED")
            
            return False
    except Exception as e:
        print("[!]Error extracting deregistration request: ")
        traceback.print_exc()
        return None

def packet_processing(pkt):
    """
    In case of N1/N2 Interface we are looking for NGAP segments.
    Following approach: 
    1. identify SCTPChunkData, envelope of NGAP data
    2. identify NGAP 
    3. dissect/deserialize NGAP
    4. store packet and deserialized data in special queues -> Other function(process) will extract items from queues and work with them
    """
    global pkt_counter
    try:
        if pkt.haslayer(SCTPChunkData):
            chunk = pkt[SCTPChunkData]
            chunk_data = chunk.data  # Extract SCTP Data chunk payload

            #data length check
            if len(chunk_data) == 0:
                    print("[-] Empty chunk data")
                    return
            
            if chunk.proto_id == 60:    #NGAP has proto id 60

                if len(chunk_data) % 4 != 0:        #NEEDED?
                    # If it's not aligned, manually pad it
                    padding_needed = 4 - (len(chunk_data) % 4)
                    chunk_data += b'\x00' * padding_needed  # Manually add padding
                    #print(f"[DEBUG] Padded Data Length: {len(chunk_data)}")
                
                pkt_counter += 1
                print(f"[+] Processing NGAP packet #{pkt_counter}")
                Qmanager.put('qngap',pkt)   #store pkt as ngap 
        Qmanager.put('qpkt', pkt)   #store pkt
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

def sniff_packets(dump,test):
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
    
    print("[+]Sniffing for packets...", flush=True)
    packets = sniff(iface="br-free5gc",
                    filter="sctp port 38412",
                    prn=lambda packet: Qmanager.put('qpkt',packet),
                    store=False)    #port
    
        
        

def graceful_shutdown(signal):
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
    free5gc_proc = multiprocessing.Process(target=start_free5gc)
    interface_proc= multiprocessing.Process(target=sniff_packets, args=(arg.dump,arg.test,))
    print(f"[+][{time.strftime('%Y%m%d_%H:%M:%S')}] Starting Free5GC")
    Qmanager.add_queue('qngap')
    
    free5gc_proc.start()
    interface_proc.start()

    if tests[arg.test]["name"] == "TC_AMF_NAS_INTEGRITY_FAILURE":
        free5gc_proc.join()

        print(f"[+] Test case: {tests[arg.test]['name']} selected")
        test_nas_integrity_failure = multiprocessing.Process(target=tc_amf_nas_integrity_failure, args=())
        test_nas_integrity_failure.start()
        test_nas_integrity_failure.join() 
        
        
    interface_proc.join()

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
from MyNGAPdissector import NAS, NGAP
#from MyTest import *
from scapy.all import sniff, PcapWriter, Ether, SCTPChunkData, SCTP, IP, wrpcap

pkt_counter = 0
script_dir = os.path.dirname(os.path.abspath(__file__))
qpkt = multiprocessing.Queue()

""""""
class Testbench:
    """Definition of Available Test Cases"""
    tests = {
        -1: {
            "name": "ANY",
            "group": "ANY",
            "NFs": "ANY"
        },
        0: {
            "name": "tc_amf_nas_integrity_failure",
            "group": "NGAP/NAS",
            "NFs": "AMF"
        },
        1: {
            "name":"tc_nas_replay_amf",
            "group":"NGAP/NAS",
            "NFs":"AMF"
        },
        2: {
            "name":"tc_nas_null_int_amf",
            "group":"NGAP/NAS",
            "NFs":"AMF"
        }
    }



    def __init__(self, tests):
        manager = multiprocessing.Manager()
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.pktparser = multiprocessing.Process(target = self.__pktparser) #PARALLEL data filter
        self.td_test = self.__test_parser(tests)
        self.history = manager.list() 
        self.amfip = manager.Value('s','')
        self.lock = multiprocessing.Lock()  
        self.pktcounter = 0


    
    def __test_parser(self,test_arg):
        """
        Construct a list with all the test required by the user
        """
        testl = []
        try:
            if isinstance(test_arg, int):
                testl.append(test_arg)
            if test_arg == -1:
                #ANY
                testl = list(range(0,len(tests)))
            elif "," in test_arg:
                testl = [int(v.strip()) for v in test_arg.split(",")]
            elif "-" in test_arg:
                start, end = map(int, test_arg.split("-"))
                testl = list(range(start,end+1))
            
            if any(x not in self.tests.keys() for x in testl):
                #Invalid test case
                return None
            
            return testl
        except Exception as e:
            print("[!] Error parsing test cases. ")
            traceback.print_exc()
            return None

    def __pktparser(self):
        """
        This function populates self.history continuously without overloading scapy sniff func
        and saves pkt captures in pcap file
        """
        print("[+] TestBench Packet parser started")
        self.amfip.value = self.__container_ip('amf') #When this function run containers are up and ready
        try:
            filename = "SCAS_" + time.strftime("%Y%m%d_%H%M") + ".pcap"
            rel_path = script_dir + "/../ws_captures/" + filename
            manager = multiprocessing.Manager()
            pcap = PcapWriter(rel_path, append = True, sync = True)

            ngap = NGAP()
            while True:
                pkt = qpkt.get()
                """CONSIDER TO USE A STOPPING CONDITION eg. if pkt is None - Sent by packet processing func"""

                self.pktcounter += 1
                if pkt.haslayer(SCTPChunkData) and pkt[SCTPChunkData].proto_id == 60:
                    ngap.dissect_ngap_pdu(pkt[SCTPChunkData].data)
                    nas_pdu = ngap.get_nas_pdu() 
                    if nas_pdu is not None:
                        #NO NAS PDU
                        """
                        History is usefull for later access of packets. Only for TEST INTERESTING DATA 
                        """
                        with self.lock:
                            self.history.append(manager.dict({"ID":self.pktcounter, "RAW": pkt.data, "NAS": nas_pdu, "_scanned": False}))
                pcap.write(pkt)
                
        except Exception as e:
            print("[!] Error parsing network traffic from queue..")
            traceback.print_exc()
            exit(0)



    @staticmethod
    def __container_ip(container):
        """
        Function that retrieves container's ip 
        """
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

    
    
    @staticmethod
    def __ueransim_ue_interaction(command):
        """
        Function that interact with UERANSIM UE shell running nr-cli commands
        Useful for status retrieval or other interaction needed with the ue
        -> Strongly dependent to free5gc
        """
        retrieve_UEs = """./nr-cli -d"""    #retrieve available UEs
        if command not in {"info","status","timers","coverage","ps-establish","ps-list","ps-release","ps-release-all","deregister"}:
            #ensure asking for a valid command
            print("[!]Invalid command")
            return None
        try:
            """retrieve available UEs"""
            output = subprocess.run(["docker", "exec", "-it", "ue", "/bin/sh", "-c", retrieve_UEs], capture_output=True, text=True)
            #print("captured output(imsi):"+output.stdout)
            imsi = output.stdout.strip()    #remove /n from the output to avoid breaking shell   
            #print("imsi:"+imsi)
            run_command = f"""./nr-cli {imsi} --exec {command}"""   
            #print("run_command:"+run_command)
            """run required command"""
            output = subprocess.run(["docker", "exec", "-it", "ue", "/bin/sh", "-c", run_command], capture_output=True, text=True)
            return output.stdout
        except Exception as e:
            print("[!]Error interacting with UERANSIM UE shell: ", e)
            return None

    
    @staticmethod
    def __sctp_send(ip, port, raw_message):
        """
        Create sctp association and send message
        """
        sctp_socket = sctp.sctpsocket_tcp(socket.AF_INET)

        sctp_socket.bind(('0.0.0.0', 5000))

        print(f"[+] SCTP Connection to AMF at {ip}:{port}")
        sctp_socket.connect((ip,port))

        sctp_socket.send(raw_message)
        print(f"[+] SCTP message sent!")

        sctp_socket.close()


    def __ue_check_alive(self):
        """Returns control only one UE is alive"""
        while True:
            ue_status = self.__ueransim_ue_interaction("status")   #Strongly dependent on free5gc
            if "MM-REGISTERED" not in ue_status or "RM-REGISTERED" not in ue_status:
                """ 
                Sync with ue waiting for registration  
                """
                print("[!] UE not yet Registered")
                #print(ue_status)
                time.sleep(2)
                continue
            else:
                print("[+] UE Registered")
                break
        return True
    

    
    def __search_NAS_message(self, msg, fresh = True):
        """
        INPUT: 'msg' to look for, 'fresh' if you look for a fresh msg or an old one is good enough 
        Look for msg into history with some precautions
        1. Ensure to be in time for the message, not too early. Kindly wait some time for the message, in case it got delayed :)
        2. Because of replay - or anything - there could be more message_type of the same kind, handle the dopplegangers. Always scan the whole history
        """
        attempt = 0
        print(f"[+] Searching for {msg} message")
        while not self.history:
            """ Polling in case history still empty """
            time.sleep(1)
        
        while True:

            attempt += 1
            ret = None

            for item in range(len(self.history)):
                t = self.history[item]
                if msg in t["NAS"]["PlainNASPDU"]["message_type"]:
                    if t['_scanned'] is False:
                        """ Fresh value """
                        with self.lock:
                            self.history[item]['_scanned'] = True
                        print(f"[+] Found {msg} FRESH message!")
                        ret = self.history[item]
                    elif (t['_scanned'] is True) and (fresh is False):
                        """ Old value, but fair enough"""
                        print(f"[+] Found {msg} OLD message!")
                        ret = self.history[item]

                """Everytime this function is called, everything is _scanned"""
                with self.lock:
                    self.history[item]['_scanned'] = True
            
            """ 
            While True exit conditions.
            If not found, wait for it - just a bit  
            Looking for it 3 times, roughly 3s should be enough for every response/processing synchronization 
            """  
            if ret is not None:
                break
            if attempt == 3:
                print(f"[!] No {msg} message found in history ")
                break
            else:
                print(f"[*] {attempt} attempt failed looking for {msg} message into history...")
                time.sleep(1)
        
        return ret
    


    """
    Test case: TC_NAS_REPLAY_AMF

    AMF supports integrity protection of NAS-signalling as speficied in TS 33.501 clause 5.5.2

    Execution Steps: 
    1.	The tester shall capture the NAS Security Mode Command procedure taking place between UE and AMF over N1 interface using any network analyser.
    2.	The tester shall filter the NAS Security Mode Complete message by using a filter.
    3.	The tester shall replay the captured NAS Security Mode Complete message.
    4.	The tester shall check whether the replayed NAS Security Mode Complete message was not processed by the AMF by capturing traffic over the N1 interface 
        to see if no corresponding response message was sent by the AMF. If applicable, AMF application logs could be checked for the rejection of the replayed     
        NAS Security Mode Complete message.
    """
    def tc_nas_replay_amf(self,pipe):
        print("[+] tc_nas_replay_amf test case STARTED")

        self.__ue_check_alive()
        print("[+] UE Alive & Registered ")

        """Capture NAS Security Mode Complete message, not necessary the last received one"""
        
        msg = self.__search_NAS_message('Security mode complete', False)

        if msg is None:
            print("[!] Somehow Security Mode Complete message not found in history...")
            exit(0)

        """Replay Security Mode Complete message"""
        
        self.__sctp_send(self.amfip.value, 38412, msg['RAW'])

        """ Check whether the SMC was not processed by the AMF --> Looking for Registration Accept """

        ret = self.__search_NAS_message("Registration Accept")
        if ret is None:
            #Not found, TEST PASSED
            pipe.send(True)
        else:
            #Found, TEST FAILED
            pipe.send(False)
    
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
    def tc_amf_nas_integrity_failure(self,pipe):
        print("[+] amf_nas_integrity test case STARTED")

        self.__ue_check_alive()
        
            
        """ 
        2. The AMF sends the Security Mode Complete message to the UE.
        scan q looking for Security Mode Complete message 
        """

        msg = self.__search_NAS_message('Security mode complete')

                
        """ 
        3. After the Security Mode Complete message, send a NAS message from the UE to the AMF with a wrong NAS-MAC. 
        The message used must not be an exception in TS 24.501 [5].
        grub a NAS message from the history from which AMF reaction is expected 
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
            file_path = os.path.join(script_dir, "../data/hex_dereg_req.json")
            """ 
            hex_dereg_req.json is extracted from the particular free5gc instance 
            I'm using in this study. For other instances, consider regenerate the
            file to better fit your environment.  
            
            """
            with open(file_path) as f:
                data = json.load(f)
        except Exception as e:
            print("[!]Error extracting deregistration request: ")
            traceback.print_exc()
            return None
        
        ngap = NGAP()
        """Using dissected json for easier modification of target fields """
        ngap.dissect_ngap_pdu(bytes.fromhex(data["ngap"]))
        print("[+] Injecting DEREGISTRATION REQUEST with wrong NAS-MAC")
        
        print("[+] Untampered Deregistration Retrieved")
        #ngap.print_ngap()   #In case any further clearence is needed
        mac = ngap.segment["Initiating Message"]["IEs"]["id-NAS-PDU"]["NAS PDU"]["SecurityProtectedNASPDU"]["mac"]
        mac_bytes = bytes.fromhex(mac)
        mac_bytes = b'\xff\xff\xff\xff'  #overwrite mac
        mac = mac_bytes.hex()
        print(f"[+] --> Tampered MAC with 0xff: {mac}")
        ngap.segment["Initiating Message"]["IEs"]["id-NAS-PDU"]["NAS PDU"]["SecurityProtectedNASPDU"]["mac"] = mac
        print("[+] Tampered Deregistration Crafted")
        #ngap.print_ngap()

        raw_ngap = ngap.build_ngap_pdu(ngap.segment)
        self.__sctp_send(self.amfip.value,38412,raw_ngap)

        """
        Evaluate test result.
        AMF DISCARD NAS MESSAGE
        --> BEST option, look for DEREGISTRATION RESPONSE FOR A CERTAIN AMOUNT OF TIME
            IF NONE, TEST PASS. IF ANY TAST FAILS. 
        --> ALSO, look at the UE MM status, if still registered tast fails.
        """    

        ret = self.__search_NAS_message('Deregistration accept')
        if ret is None:
            #Not found, TEST PASSED
            pipe.send(True)
        else:
            #Found, TEST FAILED
            pipe.send(False)                                                                                

    def tc_nas_null_int_amf(self,pipe):
        """
        NIA0 is disabled in AMF in the deployments where support of unauthenticated emergency session is not a regulatory requirement 
        as specified in TS 33.501 [2], clause 5.5.2
        Expected Results:
        In both emergency and non-emergency registrations, the UE was successfully authentication and the integrity algorithm selected 
        by the AMF in the NAS SMC message is different from NIA0.
        The NAS Security Mode Command message is integrity protected by the AMF.
        """
        print(f'[+] tc_nas_null_int_amf test case STARTED')

        """ 
        non-emergency registrations already performed at startup 
        1. ensure UE registered
        """
        self.__ue_check_alive()
        
        """
        2. inspect Security Mode Command 
        """

        smc = self.__search_NAS_message('Security mode command', False)
        if smc is not None:
            
            algs = NAS.dissect_NAS_Sec_Alg(smc['NAS'])
            if algs is not None:
                """ Algorithms correctly issued"""
                integrity = algs[1]
                if integrity == '5GIA0':
                    """Test Failed"""
                    pipe.send(False)
                else:
                    """Test Passed"""
                    pipe.send(True)
                
                print(f'[+] Integrity Algorithm Used in Security Mode Command {integrity}')
            else:
                print(f'[!] Security Mode Command not Integrity Protected - or Error during NAS dissecting')
                pipe.send(False)

def start_free5gc():
    try:
        os.system("docker compose -f /home/vincenzo_d/free5gc-compose/docker-compose.yaml up -d >/dev/null 2>&1")
    except Exception as e:
        print("Error starting Free5GC:", e, flush=True)

def sniff_packets():
    """ 
    waiting interface ready
    """
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
    
    

    print("[+] Sniffing for packets...", flush=True)
    packets = sniff(iface="br-free5gc",
                    filter="sctp port 38412",
                    prn=lambda packet: qpkt.put(packet),
                    store=False)    
    
        
        
def graceful_shutdown(signal=None,frame=None):
    """ 
    Function to handle cleanup and shutdown gracefully
    When multi-process a signal is caught by every process and this function is called multiple times. Watch out>>>Find a method to fix the behavior 
    """
    print(f"\nGracefully shutting down docker.")
    subprocess.run(["docker", "compose", "-f", "/home/vincenzo_d/free5gc-compose/docker-compose.yaml", "down"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("Docker Compose shutdown completed.")
    exit(0)

signal.signal(signal.SIGINT, graceful_shutdown) 


    
if __name__ == "__main__":
    # Parse arguments
    argparser = argparse.ArgumentParser(description="Free5GC Network Sniffer")
    argparser.add_argument("--test",type=str, dest="test", help="Select test case, default 'ANY'. Comma separated values and range values supported . --tests-enum lists available tests", default=-1)
    argparser.add_argument("--test-enum", action="store_true", help="Show every test available")
    arg = argparser.parse_args()

    global testbench
    testbench = Testbench(arg.test)

    if testbench.td_test is None:
        argparser.print_help()
        print(f"[!]Available tests: \n {testbench.tests}")
        exit(0)

    if arg.test_enum:
        tests = json.dumps(testbench.tests,indent=4)
        print(tests)
        exit(0)

    

    # Start Free5GC containers.
    free5gc_proc = multiprocessing.Process(target=start_free5gc)
    sniffer = multiprocessing.Process(target=sniff_packets)
    print(f"[+] [{time.strftime('%Y%m%d_%H:%M:%S')}] Starting Free5GC")
    
    """ Start Free5gc Docker env """
    free5gc_proc.start()

    """ Start Sniffing """
    sniffer.start()

    free5gc_proc.join()

    """ Once free5gc is ready start parsing data"""
    testbench.pktparser.start()



    """
    Running tests in self.td_test
    """
    parent_pipe, child_pipe = multiprocessing.Pipe() 

    for test in testbench.td_test:
        fun = getattr(testbench,testbench.tests[test]['name'],None)
        if callable(fun):
            #print(f'[DEBUG] Running test {testbench.tests[test]["name"]}')
            t = multiprocessing.Process(target = fun, args=(child_pipe,))
            t.start()
            result = parent_pipe.recv()
            if result:
                print(f"[+] Test {testbench.tests[test]['name']} PASSED!")
            else:
                print(f"[+] Test {testbench.tests[test]['name']} FAILED!")
            t.join() 
        else:
            print(f'[!] Method {testbench.tests[test]["name"]} not found')

    """
    End gracefully
    """
    sniffer.terminate()
    sniffer.join()

    testbench.pktparser.terminate()
    testbench.pktparser.join()
    
    graceful_shutdown()



        
    

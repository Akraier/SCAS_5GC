import multiprocessing
import subprocess
import signal
import time
import json
#import sctp
import socket
import logging
import argparse
import traceback
import os
import asn1tools
from binascii import unhexlify
from MyNGAPdissector import NAS, NGAP, nas_int_algs, nas_enc_algs
from scapy.all import sniff, PcapWriter, Ether, SCTPChunkData, SCTP, IP, wrpcap

pkt_counter = 0
PROXY_IP = "10.100.200.200"
PROXY_PORT = 1337
script_dir = os.path.dirname(os.path.abspath(__file__))
qpkt = multiprocessing.Queue()

""""""
class Testbench:
    """Definition of Available Test Cases"""
    tests = {
        0: {
            "name": "ANY",
            "group": "ANY",
            "NFs": "ANY"
        },
        1: {
            "name": "tc_amf_nas_integrity_failure",
            "group": "NGAP/NAS",
            "NFs": "AMF",
            "Result": ""
        },
        2: {
            "name":"tc_nas_replay_amf",
            "group":"NGAP/NAS",
            "NFs":"AMF",
            "Result": ""
        },
        3: {
            "name":"tc_nas_null_int_amf",
            "group":"NGAP/NAS",
            "NFs":"AMF",
            "Result": ""
        },
        4: {
            "name":"tc_ue_sec_cap_as_context_setup",
            "group":"NGAP/NAS",
            "NFs":"AMF",
            "Result": ""
        },
        5: {
            "name":"tc_ue_sec_cap_handling_amf",
            "group":"NGAP/NAS",
            "NFs":"AMF",
            "Result": ""
        }
    }



    def __init__(self, tests):
        manager = multiprocessing.Manager()
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.pktparser = multiprocessing.Process(target = self.__pktparser) 
        self.td_test = self.__test_parser(tests)
        self.history = manager.list() 
        self.amfip = manager.Value('s','')
        self.nas_seq_num = manager.Value('i',0) 
        self.lock = multiprocessing.Lock()  
        self.pktcounter = 0


    
    def __test_parser(self,test_arg):
        """
        Construct a list with all the test required by the user
        """
        testl = []
        try:
            
            if test_arg == "0":
                testl = list(range(1,len(self.tests)))
            elif "," in test_arg:
                testl = [int(v.strip()) for v in test_arg.split(",")]
            elif "-" in test_arg:
                start, end = map(int, test_arg.split("-"))
                testl = list(range(start,end+1))
            elif test_arg.isdigit():
                testl.append(int(test_arg))

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
                            self.history.append(manager.dict({"ID":self.pktcounter, "RAW": pkt.data, "NGAP": ngap.segment, "NAS": nas_pdu, "_scanned": False}))
                            if nas_pdu.get("SecurityProtectedNASPDU") is not None:
                                self.nas_seq_num.value = nas_pdu["SecurityProtectedNASPDU"]["seq_no"] + 1
                    else:
                        #NGAP PDU without NAS
                        with self.lock:
                            self.history.append(manager.dict({"ID":self.pktcounter, "RAW": pkt.data, "NGAP": ngap.segment, "_scanned": False}))
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

    


    def __ue_check_alive(self):
        """Returns control only one UE is alive"""
        while True:
            ue_status = self.__ueransim_ue_interaction("status")   #Strongly dependent on ueransim
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
    
    def __search_NGAP(self, msg):
        """
        Search NGAP IE into history, less restrictive than NAS search. Don't care about freshness
        INPUT: msg to look for, add(itional information)s for the search {'ie':id-}
        OUTPUT: list of dict Segment/IE of every NGAP message containing the IE 
        """
        while not self.history:
            """ Polling in case history still empty """
            time.sleep(1)

        ret = []

        for item in range(len(self.history)):
            with self.lock:
                ngap = next(iter(self.history[item]["NGAP"]))
                if self.history[item]["NGAP"][ngap].get("procedure_code") == msg:
                    ret.append(self.history[item])
        return ret
        
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
                with self.lock:
                    t = self.history[item].get("NAS",None)
                    h = self.history[item] 
                if (t is not None) and (msg in t["NAS PDU"]["PlainNASPDU"]["message_type"]):
                    if h['_scanned'] is False:
                        """ Fresh value """
                        with self.lock:
                            self.history[item]['_scanned'] = True
                        print(f"[+] Found {msg} FRESH message!")
                        ret = self.history[item]
                    elif (h['_scanned'] is True) and (fresh is False):
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
    def tc_nas_replay_amf(self, pipe, ctrl_pipe):
        print("[+] tc_nas_replay_amf test case STARTED")

        self.__ue_check_alive()
        print("[+] UE Alive & Registered ")

        """Capture NAS Security Mode Complete message, not necessary the last received one"""
        
        msg = self.__search_NAS_message('Security mode complete', False)
        
        if msg is None:
            print("[!] Somehow Security Mode Complete message not found in history...")
            exit(0)

        """Replay Security Mode Complete message"""
        smc_raw = NGAP()
        smc_raw = smc_raw.build_ngap_pdu(msg.get("NGAP"))
        smc = {"testCase":"tc_nas_replay_amf",
               "msg": smc_raw.hex()}
        ctrl_pipe.send(smc)
        print(f"[+] Security Mode Complete message sent to Controller")


        """ Check whether the SMC was not processed by the AMF --> Looking for Registration Accept """
        test_result = ctrl_pipe.recv()
        if test_result == "Test OK":
            print(f"[+] Test OK", flush=True)
            ret = self.__search_NAS_message('Registration accept')
            if ret is None:
                pipe.send(True)
            else:
                pipe.send(False)
        elif test_result == "Test KO":
            print(f"[!] Test KO", flush=True)
            pipe.send(False)
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
    def tc_amf_nas_integrity_failure(self,pipe, ctrl_pipe):
        print("[+] amf_nas_integrity test case STARTED")

        self.__ue_check_alive()
        
            
        """ 
        2. The AMF sends the Security Mode Complete message to the UE.
        scan q looking for Security Mode Complete message 
        """

        msg = self.__search_NAS_message('Security mode complete')
        if msg is None:
            print("[!] Somehow Security Mode Complete message not found in history...")
            pipe.send(False)
            return
                
        """ 
        3. After the Security Mode Complete message, send a NAS message from the UE to the AMF with a wrong NAS-MAC. 
        The message used must not be an exception in TS 24.501 [5].
        grub a NAS message from the history from which AMF reaction is expected 
        """
       
        dereg_ngap = "002e4043000004000a0002000100550002000100260019187e02b9ddb068047e004501000bf202f839cafe0000000001007940135002f839000000010002f839000001eb856406"
        ngap = NGAP()
        ngap.dissect_ngap_pdu(bytes.fromhex(dereg_ngap))
        print("[+] Injecting DEREGISTRATION REQUEST with wrong NAS-MAC")
        
        print("[+] Untampered Deregistration Retrieved")
        """MAC tampering"""
        mac = ngap.segment["Initiating Message"]["IEs"]["id-NAS-PDU"]["NAS PDU"]["SecurityProtectedNASPDU"]["mac"]
        mac_bytes = bytes.fromhex(mac)
        mac_bytes = b'\xff\xff\xff\xff'  #overwrite mac
        mac = mac_bytes.hex()
        print(f"[+] --> Tampered MAC with 0xff: {mac}")
        ngap.segment["Initiating Message"]["IEs"]["id-NAS-PDU"]["NAS PDU"]["SecurityProtectedNASPDU"]["mac"] = mac

        """Adequating necessary values """
        ngap.segment["Initiating Message"]["IEs"]["id-NAS-PDU"]["NAS PDU"]["SecurityProtectedNASPDU"]["seq_no"] = self.nas_seq_num.value

        print("[+] Tampered Deregistration Crafted")
        raw_msg = ngap.build_ngap_pdu(ngap.segment).hex()

        ctrl_data = {
            "testCase": "tc_amf_nas_integrity_failure", 
            "msg": raw_msg
        }
        
        ctrl_pipe.send(ctrl_data)

        """
        Evaluate test result.
        AMF DISCARD NAS MESSAGE
        --> BEST option, look for DEREGISTRATION RESPONSE FOR A CERTAIN AMOUNT OF TIME
            IF NONE, TEST PASS. IF ANY TAST FAILS. 
        --> ALSO, look at the UE MM status, if still registered tast fails.
        """    
        test_result = ctrl_pipe.recv()
        if test_result == "Test OK":
            print(f"[+] Test OK", flush=True)
            ret = self.__search_NAS_message('Deregistration accept')
            if ret is None:
                pipe.send(True)
            else:
                pipe.send(False)
        elif test_result == "Test KO":
            print(f"[!] Test KO", flush=True)
            pipe.send(False)
            return
        

    def tc_nas_null_int_amf(self, pipe, ctrl_pipe):
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
            print(f"[+] Extracting Integrity Algorithm from Security Mode Command...")
            algs = NAS.dissect_NAS_Sec_Alg(smc['NAS'])
            try:
                nas_smc = smc['NAS']
                msg_v = nas_smc.get('NAS PDU').get('PlainNASPDU').get('message_value')
                if msg_v is not None:
                    raw_msg = bytes.fromhex(msg_v)
                    security_algs = raw_msg[0]

                    """4 LSBits"""
                    int_alg = nas_int_algs[security_algs & 0x0F]
                    """4 MSBits"""
                    cipher_alg = nas_enc_algs[(security_algs & 0xF0) >> 4]
                    
                else:
                    print('[!] Wrong NAS PDU')
                    return None
                
                if int_alg == '5GIA0':
                    """Test Failed"""
                    pipe.send(False)
                else:
                    """Test Passed"""
                    pipe.send(True)

                    print(f'[+] Integrity Algorithm Used in Security Mode Command {int_alg}')
                    print(f'[+] Integrity Algorithm Used in Security Mode Command {cipher_alg}')
            except Exception as e:
                print(f'[!] Error during NAS dissecting: {e}')
                pipe.send(False)
                traceback.print_exc()
    
    def tc_ue_sec_cap_as_context_setup(self, pipe, ctrl_pipe):
        """Verify that the UE security capabilities sent by the UE in the initial NAS registration request are the same 
           UE security capabilities sent in the NGAP Context Setup Request message to establish AS security."""
        """ Registration Request(Simple) and Context Setup(ASN1 PER) use different encodings for UE Security Capabilities.
            Registration Request encode capabilities using 8 bits, one bit for each algorithm.
            Context Setup encode capabilities using 16 bits, one bit for each algorithm plus reserved bits. EA0 and IA0 are encoded with all bits set to 0 rather than setting the corresponding bit to 1.
            For this reason we need to convert values in a single encoding before comparing them. For the sake of simplicity we will use Registration Request encoding."""


        print('[+] tc_ue_sec_cap_as_context_setup STARTED')

        """ Look for NGAP Context Setup Request """
        context_setup = self.__search_NGAP("id-InitialContextSetup") 
        """ Extract UE Sec Capabs NGAP TS 9.3.1.86"""
        

        next_ = next(iter(context_setup[0]["NGAP"]))
        raw_cap = context_setup[0]["NGAP"][next_]["IEs"]["id-UESecurityCapabilities"]["IE_value"]       #1c000e000000000000

        """ PER DEcoding of the UESecurityCapabilities """
        specs = asn1tools.compile_files('UE_Sec_Cap.asn', codec='uper')
        ue_caps = specs.decode('UESecurityCapabilities', unhexlify(raw_cap))
        context_setup_supported = {}

        for key in ue_caps.keys():
            context_setup_supported[key] = ''.join(format(byte, '08b') for byte in ue_caps[key][0])
            context_setup_supported[key] = '1' + context_setup_supported[key][1:8]  # exclude reserved bits and PER first bit and substitute with 1, A0 always supported

        """ print(f"[+] nRencryptionAlgorithms {context_setup_supported['nRencryptionAlgorithms']}")
        print(f"[+] nRintegrityProtectionAlgorithms {context_setup_supported['nRintegrityProtectionAlgorithms']}")
        print(f"[+] eUTRAencryptionAlgorithms {context_setup_supported['eUTRAencryptionAlgorithms']}")
        print(f"[+] eUTRAintegrityProtectionAlgorithms {context_setup_supported['eUTRAintegrityProtectionAlgorithms']}") """
        
        """ Look for Registration Request """
        registration_request = self.__search_NAS_message('Registration request', False)
        reg_req_cap = registration_request['NAS']['NAS PDU']['PlainNASPDU']['message_value'][36:]    #extracting UESecurityCapabilities from Registration Request, 4 bytes - 8 chars
        """ Convert Registration Request UESecurityCapabilities to the same format as Context Setup """
        raw_reg_req_cap = bytes.fromhex(reg_req_cap)
        raw_reg_req_cap = ''.join(format(byte, '08b') for byte in raw_reg_req_cap)
        reg_req_supported = {
            'nRencryptionAlgorithms': raw_reg_req_cap[0:8],
            'nRintegrityProtectionAlgorithms': raw_reg_req_cap[8:16],
            'eUTRAencryptionAlgorithms': raw_reg_req_cap[16:24],
            'eUTRAintegrityProtectionAlgorithms': raw_reg_req_cap[24:32]
        }

        match = True
        print(f"[+] Comparing UE security capabilities...")
        for key in reg_req_supported.keys():
            print(f"[+] {key}: [ Registration Request > {reg_req_supported[key]} | {context_setup_supported[key]} < Context Setup ]")
            if context_setup_supported[key] != reg_req_supported[key]:
                print(f"[!] {key} not matching")
                match = False
            else:
                print(f"[+] {key} matching")

        if not match:
            pipe.send(False)
        else:
            pipe.send(True)

    def tc_ue_sec_cap_handling_amf(self, pipe, ctrl_pipe):
        """
        Registration Request with unsecure UE security capabilities
        1. NO 5GS encryption algorithms (all bits 0)
        2. NO 5GS integrity algorithms (all bits 0)
        3. mandatory 5GS encryption algorithms not supported
        4. mandatory 5GS integrity algorithms not supported

        APPROACH: Craft a Registration Request with all bits set to 0 for 5GS encryption and integrity algorithms
        """

        self.__ue_check_alive()

        print("[+] tc_ue_sec_cap_handling_amf test case STARTED")

        rr = self.__search_NAS_message('Registration request', False)
        if rr is None:
            print("[!] Somehow Registration Request message not found in history...")
            pipe.send(False)
            return

        """ Extract UESecurityCapabilities from Registration Request """
        rr_cap = rr['NAS']['NAS PDU']['PlainNASPDU']['message_value']
        print(f"[+] Extracting UESecurityCapabilities from Registration Request...")
        rr_cap = rr_cap[:36] + '0' * 8 
        print(f"[+] UESecurityCapabilities modified: {rr_cap}") 
        tmp = rr['NGAP'] 
        tmp['Initiating Message']['IEs']['id-NAS-PDU']['NAS PDU']['PlainNASPDU']['message_value'] = rr_cap
        print(f"[+] Modified Registration Request with unacceptable UE Security Capabilities \n")
        """ Send modified Registration Request to proxy """
        ngap = NGAP()
        rr_segment = ngap.build_ngap_pdu(tmp)
        ctrl_data = {
            "testCase": "tc_ue_sec_cap_handling_amf",
            "msg": rr_segment.hex()
        }
        ctrl_pipe.send(ctrl_data)
        print(f"[+] Modified Registration Request sent to Proxy")
        """ Check for AMF response """
        test_result = ctrl_pipe.recv()
        if test_result == "Test OK":
            """ Look for Registration Reject """
            rrej = self.__search_NAS_message('Registration reject', True)
            if rrej is None:
                """ Test Failed"""
                print(f"[!] Registration Reject not found")
                pipe.send(False)
            else:
                """ Test Passed """
                print(f"[+] Registration Reject found")
                pipe.send(True)

        elif test_result == "Test KO":
            print(f"[!] Error injecting message through Proxy", flush=True)
            pipe.send(False)
            return

def ctrl(pipe):
    """ Function handling control connection with the proxy"""
    """ Receives data from the testCase function through the pipe
        and sends it to the proxy through the socket """
    
    sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sckt.connect((PROXY_IP, PROXY_PORT))
    print(f"[+] Control connection established with {PROXY_IP}:{PROXY_PORT}", flush=True)

    while True:
        if pipe.poll():
            """ Expected data is dict = {'testCase': tc_name, 'msg': msg} """

            data = pipe.recv()
            print(f"[CTRL] Received data from test case", flush=True)
            
            """ Exit condition """
            if data == "exit":
                print("[CTRL] Exiting control connection", flush=True)
                sckt.close()
                break

            data = json.dumps(data).encode()

            sckt.sendall(data) 
            print(f"[CTRL] Sent data to proxy", flush=True)
            sckt.settimeout(5)
            try:
                resp = sckt.recv(1024).decode('utf-8').strip()
            except socket.timeout:
                print("[!] Timeout waiting for response from proxy", flush=True)
            if resp == "Test OK":
                print(f"[CTRL] Test case executed successfully", flush=True)
                pipe.send("Test OK")
            elif resp == "Test KO":
                print(f"[CTRL] Test case execution failed", flush=True)
                pipe.send("Test KO")  
            elif not resp:
                print("[CTRL] Control connection closed by proxy", flush=True)
                sckt.close()
                break

def start_free5gc():
    try:
        command = ["docker", "compose", "-f", path, "up", "--build", "-d"]
        result = subprocess.run(command, check=True, stdout=subprocess.DEVNULL)

        if result.stderr:
            print(f"[!] Error starting Free5GC: {result.stderr.decode()}", flush=True)

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
    with open("../log/amf.log", "a") as log_file:
        subprocess.run(["docker", "logs", "amf"], stdout=log_file, stderr=subprocess.STDOUT)
    with open("../log/gnb.log", "a") as log_file:
        subprocess.run(["docker", "logs", "ueransim"], stdout=log_file, stderr=subprocess.STDOUT)
    with open("../log/ue.log", "a") as log_file:
        subprocess.run(["docker", "logs", "ue"], stdout=log_file, stderr=subprocess.STDOUT)
    with open("../log/proxy.log", "a") as log_file:
        subprocess.run(["docker", "logs", "sctp-proxy"], stdout=log_file, stderr=subprocess.STDOUT)
    subprocess.run(["docker", "compose", "-f", path, "down"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    print("Docker Compose shutdown completed.")
    exit(0)

signal.signal(signal.SIGINT, graceful_shutdown) 


    
if __name__ == "__main__":
    
    # Parse arguments
    argparser = argparse.ArgumentParser(description="Free5GC Network Sniffer")
    argparser.add_argument("--path", type=str, dest="path", help=".yaml docker compose free5gc path")
    argparser.add_argument("--test",type=str, dest="test", help="Select test case, default 'ANY'. Comma separated values and range values supported . --tests-enum lists available tests", default=-1)
    argparser.add_argument("--test-enum", action="store_true", help="Show every test available")
    arg = argparser.parse_args()

    global testbench, path
    testbench = Testbench(arg.test)
    path = arg.path

    if testbench.td_test is None or arg.test_enum:
        argparser.print_help()
        print(f"[/]Available tests:")
        for key, test in testbench.tests.items():
            print(f"[>>] Test {key} - {test['name']}")
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
    print("[+] FREE5GC Up & Running")

    """ Once free5gc is ready start parsing data"""
    testbench.pktparser.start()

    """ Create testCase-Controller pipe"""
    server_pipe, client_pipe = multiprocessing.Pipe()

    """ Create and start controller process"""
    ctrl_proc = multiprocessing.Process(target=ctrl, args=(server_pipe,)) 
    ctrl_proc.start()

    """
    Running tests in self.td_test
    """
    parent_pipe, child_pipe = multiprocessing.Pipe() 

    for test in testbench.td_test:
        fun = getattr(testbench,testbench.tests[test]['name'],None)
        if callable(fun):
            t = multiprocessing.Process(target = fun, args=(child_pipe,client_pipe))
            t.start()
            print("-----------------------")

            result = parent_pipe.recv()
            if result:
                print(f"[+] Test {testbench.tests[test]['name']} PASSED!")
                test["Result"] = "PASSED"
            else:
                print(f"[+] Test {testbench.tests[test]['name']} FAILED!")
                test["Result"] = "FAILED"
            t.join() 
            print("-----------------------")

        else:
            print(f'[!] Method {testbench.tests[test]["name"]} not found')
    client_pipe.send("exit")
    
    """
    End gracefully
    """
    sniffer.terminate()
    sniffer.join()

    ctrl_proc.terminate()
    ctrl_proc.join()

    testbench.pktparser.terminate()
    testbench.pktparser.join()
    
    graceful_shutdown()

    print("[+] TEST COMPLETED:")
    for test in testbench.tests:
        print(f"[>>] Test {test['name']} - {test['Result']}")

        
    

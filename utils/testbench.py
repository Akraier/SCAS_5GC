
import os, multiprocessing, subprocess, traceback, time, asn1tools
from utils.MyNGAPdissector import *
from scapy.all import *
from binascii import unhexlify
from ruamel.yaml import YAML

class Testbench:
    available_tests = {
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
        },
        6: {
            "name":"tc_guti_allocation_amf",
            "group":"NGAP/NAS",
            "NFs":"AMF",
            "Result": ""
        },
        7: {
            "name":"tc_nas_int_selection_use_amf",
            "group":"NGAP/NAS",
            "NFs":"AMF",
            "Result": ""
        }
    }

    def __test_parser(self, test_arg):
        """
        Construct a list with all the test required by the user
        """
        testl = []
        try:
            
            if test_arg == "0":
                testl = list(range(1,len(self.available_tests)))
            elif "," in test_arg:
                testl = [int(v.strip()) for v in test_arg.split(",")]
            elif "-" in test_arg:
                start, end = map(int, test_arg.split("-"))
                testl = list(range(start,end+1))
            elif test_arg.isdigit():
                testl.append(int(test_arg))

            if any(x not in self.available_tests.keys() for x in testl):
                #Invalid test case
                print(f"[!] {x} is not a valid test case.")
                return None
            
            return testl
        except Exception as e:
            print("[!] Error parsing test cases. ")
            traceback.print_exc()
            return None

    @staticmethod
    def __container_ip(container):
        """
        Function that retrieves container's ip 
        Will this work for open5gs and others?
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

    def __init__(self, tests, path):
        self.manager = multiprocessing.Manager()
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.tests = self.__test_parser(tests)
        self.history = self.manager.list()
        self.qpkt = multiprocessing.Queue() #Queue for packet capture
        self.amfip = self.manager.Value('s','')
        self.lock = multiprocessing.Lock()
        self.simulator_proxy_ip = "10.100.200.200"
        self.simulator_proxy_port = 1337
        self.result = self.manager.dict()
        if 'free5gc' in path:
            self.simulator_name = "free5gc"
            self.simulator_path = path
            self.simulator_config_path = os.path.join(path, "config")
            self.simulator_docker_compose = os.path.join(path, "docker-compose.yaml")
            self.simulator_interface = "br-free5gc"
            self.nfs = {
                "amf": "amf",
                "gnb": "ueransim",
                "ue": "ue",
                "proxy": "sctp-proxy"
            }
        #Other simulators missing... TBD
    def _saveLog(self):
        log_dir = os.path.join(self.script_dir, "../log")
        logs = []
        for x in ["amf", "gnb", "ue", "proxy"]:
            logs.append((self.nfs[x],f"{x}.log"))
        

        for nf, log_file in logs:
            log_path = os.path.join(log_dir, log_file)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            with open(log_path, 'a') as f:
                subprocess.run(["docker", "logs", nf], stdout=f, stderr=subprocess.STDOUT)

    def graceful_shutdown(self,cmd_q, signal=None,frame=None):
        """ 
        Function to handle cleanup and shutdown gracefully
        When multi-process a signal is caught by every process and this function is called multiple times. Watch out>>>Find a method to fix the behavior 
        """
        print(f"\nGracefully shutting down docker.")
        self._saveLog()
        cmd_q.put(("shutdown_all",None))  # Notify the procManager to shutdown all processes
        
        subprocess.run(["docker", "compose", "-f", self.simulator_docker_compose, "down"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Docker Compose shutdown completed.")
        exit(0)

    def manage_core_simulator(self,cmd_q, action="start"):
        """
        Start or restart the core simulator.

        :param action: 'start' or 'restart'
        :param rebuild: if True, run 'up --build --force-recreate' to apply any changes
        """
        if action not in ("start", "restart"):
            raise ValueError(f"[!] Action must be 'start' or 'restart', got '{action}'")

        if action == "start":
            command = [
                "docker", "compose", "-f", self.simulator_docker_compose,
                "up", "--build", "-d"
            ]
            operation = "Starting"
            error_prefix = "Error starting"
        else:
            command = [
                "docker", "compose", "-f", self.simulator_docker_compose,
                "restart"
            ]
            operation = "Restarting"
            error_prefix = "Error restarting"

        try:
            result = subprocess.run(
                command,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except subprocess.CalledProcessError as e:
            error_message = e.stderr.decode(errors="ignore").strip() or str(e)
            print(f"[+] {error_prefix} core simulator: {error_message}", flush=True)
            raise RuntimeError(f"{error_prefix} core simulator: {error_message}") from e
        except Exception:
            print(f"[!] Unexpected error during {action} core simulator", flush=True)
            raise

        print(f"[+] {operation} core simulator succeeded", flush=True)
        return result



    def pktparser(self, cmd_q):
        """
        This function populates self.history continuously without overloading scapy sniff func
        and saves pkt captures in pcap file
        """
        print("[+] TestBench Packet parser started")
        self.amfip.value = self.__container_ip(self.nfs["amf"]) #When this function run containers are up and ready
        try:
            filename = "SCAS_" + time.strftime("%Y%m%d_%H%M") + ".pcap"
            capture_dir = os.path.normpath(os.path.join(self.script_dir, os.pardir, "ws_captures"))
            os.makedirs(capture_dir, exist_ok=True)
            capture_file = os.path.join(capture_dir, filename)
            pcap = PcapWriter(capture_file, append = True, sync = True)

            ngap = NGAP()
            while True:
                pkt = self.qpkt.get()
                """CONSIDER TO USE A STOPPING CONDITION eg. if pkt is None - Sent by packet processing func"""

                if pkt.haslayer(SCTPChunkData) and pkt[SCTPChunkData].proto_id == 60:
                    ret = ngap.dissect_ngap_pdu(pkt[SCTPChunkData].data)
                    if ret == 0:
                        print(f"[!] Error parsing NGAP PDU")
                    nas_pdu = ngap.get_nas_pdu() 
                    if nas_pdu is not None:
                        #NO NAS PDU
                        """
                        History is usefull for later access of packets. 
                        """
                        with self.lock:
                            self.history.append(self.manager.dict({"RAW": pkt.data, "NGAP": ngap.segment, "NAS": nas_pdu, "_scanned": False}))
                            if nas_pdu.get("SecurityProtectedNASPDU") is not None:
                                self.nas_seq_num.value = nas_pdu["SecurityProtectedNASPDU"]["seq_no"] + 1
                    else:
                        #NGAP PDU without NAS
                        with self.lock:
                            self.history.append(self.manager.dict({"RAW": pkt.data, "NGAP": ngap.segment, "_scanned": False}))
                pcap.write(pkt)
        except Exception as e:
            print("[!] Error parsing network traffic from queue..")
            traceback.print_exc()
            cmd_q.put(("shutdown_all",None)) 
            exit(0)
    
    @staticmethod
    def __ueransim_ue_interaction(command):
        """
        Function that interact with UERANSIM UE shell running nr-cli commands
        Useful for status retrieval or other interaction needed with the ue
        -> Strongly dependent to free5gc
        """
        retrieve_UEs = """./nr-cli -d"""    #retrieve available UEs
        if command not in {"info","status","timers","coverage","ps-establish","ps-list","ps-release","ps-release-all","deregister normal"}:
            #ensure asking for a valid command
            print("[!]Invalid command")
            return None
        try:
            """retrieve available UEs"""
            output = subprocess.run(["docker", "exec", "-it", "ue", "/bin/sh", "-c", retrieve_UEs], capture_output=True, text=True)
            #print("captured output(imsi):"+output.stdout)
            imsi = output.stdout.strip()    #remove /n from the output to avoid breaking shell   
            #print("imsi:"+imsi)
            run_command = f"""./nr-cli {imsi} --exec '{command}'"""   
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
    def tc_amf_nas_integrity_failure(self,cmd_q, ctrl_pipe):
        print("[+] amf_nas_integrity test case STARTED")

        self.__ue_check_alive()
        
            
        """ 
        2. The AMF sends the Security Mode Complete message to the UE.
        scan q looking for Security Mode Complete message 
        """

        msg = self.__search_NAS_message('Security mode complete')
        if msg is None:
            print("[!] Somehow Security Mode Complete message not found in history...")
            with self.lock:
                self.result["tc_amf_nas_integrity_failure"] = False
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
        #ngap.segment["Initiating Message"]["IEs"]["id-NAS-PDU"]["NAS PDU"]["SecurityProtectedNASPDU"]["seq_no"] = self.nas_seq_num.value #Really needed?

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
                with self.lock:
                    self.result["tc_amf_nas_integrity_failure"] = True

            else:
                with self.lock:
                    self.result["tc_amf_nas_integrity_failure"] = False

        elif test_result == "Test KO":
            print(f"[!] Test KO", flush=True)
            with self.lock:
                self.result["tc_amf_nas_integrity_failure"] = False
            return

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
    def tc_nas_replay_amf(self,cmd_q, ctrl_pipe):
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
            with self.lock:
                if ret is None:
                    self.result["tc_nas_replay_amf"]= True 
                else:
                    self.result["tc_nas_replay_amf"] = False
        elif test_result == "Test KO":
            print(f"[!] Test KO", flush=True)
            with self.lock:
                self.result["tc_nas_replay_amf"]= False
            return
    
    def tc_nas_null_int_amf(self, cmd_q, ctrl_pipe):
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
            try:
                algs = self.__get_sec_algs_from_smc(smc['NAS'])

                int_alg = nas_int_algs[algs[1]]
                cipher_alg = nas_enc_algs[algs[0]]
                with self.lock:
                    if int_alg == 'NIA0':
                        """Test Failed"""
                        self.result["tc_nas_null_int_amf"] = False 
                    else:
                        """Test Passed"""
                        self.result["tc_nas_null_int_amf"] = True 

                print(f'[+] Integrity Algorithm Used in Security Mode Command {int_alg}')
                print(f'[+] Integrity Algorithm Used in Security Mode Command {cipher_alg}')
            except Exception as e:
                print(f'[!] Error during NAS dissecting: {e}')
                self.result["tc_nas_null_int_amf"] = False 
                traceback.print_exc()
    
    def tc_ue_sec_cap_as_context_setup(self, cmd_q, ctrl_pipe):
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
        asn_file = os.path.join(self.script_dir, "UE_Sec_Cap.asn")
        specs = asn1tools.compile_files(asn_file, codec='uper')
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
            self.result["tc_ue_sec_cap_as_context_setup"] = False 
        else:
            self.result["tc_ue_sec_cap_as_context_setup"] = True 
    
    def tc_ue_sec_cap_handling_amf(self, cmd_q, ctrl_pipe):
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
            self.result["tc_ue_sec_cap_handling_amf"] = False 
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
                self.result["tc_ue_sec_cap_handling_amf"] = False 
            else:
                """ Test Passed """
                print(f"[+] Registration Reject found")
                self.result["tc_ue_sec_cap_handling_amf"] = True 

        elif test_result == "Test KO":
            print(f"[!] Error injecting message through Proxy", flush=True)
            self.result["tc_ue_sec_cap_handling_amf"] = False 
            return
    
    def tc_guti_allocation_amf(self, cmd_q, ctrl_pipe):
        """ Upon receiving Registration Request message of type "initial registration" from a UE 
        (triggered by the tester), the AMF sends a new 5G-GUTI to the UE during the registration procedure. 
        <<Upon receiving Registration Request message of type "initial registration" or "mobility registration update" 
        from a UE, the AMF *shall* send a new 5G-GUTI to the UE in the registration procedure.>>"""
        print("[+] tc_guti_allocation_amf test case STARTED")

        self.__ue_check_alive()

        """ Looking for Registration Accept """
        reg_accept = self.__search_NAS_message('Registration accept', False)
        if reg_accept is None:
            print("[!] Somehow Registration Accept message not found in history...")
            self.result["tc_guti_allocation_amf"] = False 
            return
        print(f"[+] Extracting GUTI from Registration Accept...")
        guti = reg_accept['NAS']['NAS PDU']['PlainNASPDU']['message_value'][10:50]  #extracting GUTI from Registration Accept, 16 bytes - 32 chars
        print(f"[+] #1 Registration Accept > GUTI extracted: {guti}")

        """ Force new Registration > Registration Request type: Initial Registration """
        print(f"[+] Forcing new Registration Flow...")
        dereg_result = self.__ueransim_ue_interaction("deregister normal")  
        print(f"[+] Deregistration result: {dereg_result.split()}")
        print(f"[+] Waiting for new Registration attempt...")
        while not self.__ue_check_alive():
            """ UERANSIM will try to register again """
            time.sleep(5)

        print(f"Waiting for Registration Accept...")
        new_reg_accept = self.__search_NAS_message('Registration accept', True)
        if new_reg_accept is None:
            print("[!] Somehow NEW Registration Accept message not found in history...")
            self.result["tc_guti_allocation_amf"] = False 
            return
        else:
            print(f"[+] Extracting GUTI from NEW Registration Accept...")
            new_guti = new_reg_accept['NAS']['NAS PDU']['PlainNASPDU']['message_value'][10:50]
            print(f"[+] #2 Registration Accept > GUTI extracted: {new_guti}")
            if new_guti == guti:
                print(f"[!] GUTI not changed!")
                self.result["tc_guti_allocation_amf"] = False
            else:
                print(f"[+] GUTI changed!")
                self.result["tc_guti_allocation_amf"] = True 
                return
    
    @staticmethod
    def __get_integrity_alg_from_config(amf_yaml_path):
        """
        Reads the amfcfg.yaml file and returns the first algorithm
        listed in 'integrityOrder'.
        """
        print(f"config path {amf_yaml_path}")
        yaml = YAML()
        with open(amf_yaml_path, 'r', encoding='utf-8') as f:
            cfg = yaml.load(f)
        try:
            algs = cfg['configuration']['security']['integrityOrder']
            print(f"[+] Integrity Algorithms: {algs}")
        except KeyError:
            raise KeyError(f"[!] 'integrityOrder' not found in {amf_yaml_path}")

        if not isinstance(algs, list) or len(algs) == 0:
            raise ValueError("[!] 'integrityOrder' should be a non-empty list")
        return algs

    @staticmethod
    def __modify_integrity_alg_in_config(amf_yaml_path):
        """
        Inverts priority order of integrity algorithms in amfcfg.yaml file
        """
        yaml = YAML()
        yaml.preserve_quotes = True  # mantiene le virgolette originali

        with open(amf_yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.load(f)

        algs = data['configuration']['security']['integrityOrder']
        if len(algs) < 2:
            print("[!] 'integrityOrder' should be a list with at least 2 elements")
            return False
        else:
            """ Invert the order of the first two algorithms """
            tmp = algs[0]
            data['configuration']['security']['integrityOrder'][0] = algs[1]
            data['configuration']['security']['integrityOrder'][1] = tmp
            """ UERANSIM ue can't handle emergency (NIA0/NEA0) """
            if data['configuration']['security']['integrityOrder'][0] == "NIA0" and data['configuration']['security']['cipheringOrder'][0] == "NEA0":
                """ Enable NEA2 to avoid emergency auth"""
                data['configuration']['security']['cipheringOrder'][0] = "NEA2"
            elif data['configuration']['security']['integrityOrder'][0] == "NIA2" and data['configuration']['security']['cipheringOrder'][0] == "NEA2":
                """ Restore Default """
                data['configuration']['security']['cipheringOrder'][0] == "NEA0"
            print(f"[+] Integrity Algorithms modified: {data['configuration']['security']['integrityOrder']}")
            
        with open(amf_yaml_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f)
        

    @staticmethod
    def __get_sec_algs_from_smc(NAS_PDU):
        msg_v = NAS_PDU.get('NAS PDU').get('PlainNASPDU').get('message_value')
        if msg_v is not None:
            raw_msg = bytes.fromhex(msg_v)
            security_algs = raw_msg[0]

            """4 LSBits"""
            int_alg = security_algs & 0x0F
            """4 MSBits"""
            cipher_alg = (security_algs & 0xF0) >> 4
            
            return [cipher_alg, int_alg]
        else:
            print('[!] Wrong NAS PDU')
            return None

    def __tc_nas_int_selection_use_amf_core(self,cmd_q):

        """1 Retrieve the first supported integrity algorithm from the AMF config"""
        int_algs_from_conf = self.__get_integrity_alg_from_config(self.simulator_config_path + "/amfcfg.yaml")

        """2 Security Mode Command """
        smc = self.__search_NAS_message('Security mode command', False)
        if smc is None:
            print("[!] Somehow Security Mode Command message not found in history...")
            return False

        print(f"[+] Extracting Integrity Algorithm from Security Mode Command...")
        int_alg_from_smc = nas_int_algs[self.__get_sec_algs_from_smc(smc['NAS'])[1]]
        print(f"[+] Integrity Algorithm Selected in Security Mode Command {int_alg_from_smc}")

        """3 Compare selected integrity algorithm with the one used in the Registration Request"""
        if int_alg_from_smc != int_algs_from_conf[0]:
            print(f"[!] Integrity Algorithm selected in Security Mode Command does not match the one in the AMF config")
            return False
        
        print(f"[+] Integrity Algorithm selected in Security Mode Command matches the one in the AMF config")
        print(f"[+] Modifying AMF config file...")

        """4 Modify config file inverting """
        if self.__modify_integrity_alg_in_config(self.simulator_config_path + "/amfcfg.yaml") is False:
            print("[!] Error modifying AMF config file")
            return False

        self._saveLog()
        cmd_q.put(("stop", "sniff_packets"))
        """Restart Free5GC with modified config"""
        print("[+] Restarting Free5GC with modified config...")
        subprocess.run(["docker", "compose", "-f", self.simulator_docker_compose, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] Free5GC terminated")
        
        cmd_q.put(("restart", "sniff_packets"))
        
        subprocess.run(["docker", "compose", "-f", self.simulator_docker_compose, "up", "--build", "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] Free5GC started with modified config")

        self.__ue_check_alive()
        return True
    
    def tc_nas_int_selection_use_amf(self, cmd_q, ctrl_pipe):
        """ Verify that the AMF selects the NAS integrity algorithm which has the highest priority according 
        to the ordered list of supported integrity algorithms and is contained in the 5G security capabilities supported by the UE. """
        
        print("[+] tc_nas_int_selection_use_amf test case STARTED")

        for i in range(2):
            if self.__tc_nas_int_selection_use_amf_core(cmd_q) is False:
                self.result["tc_nas_int_selection_use_amf"] = False 

                return
        self.result["tc_nas_int_selection_use_amf"] = True 
        return 
    


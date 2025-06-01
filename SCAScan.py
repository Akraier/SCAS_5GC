import time, json, yaml, socket, logging, argparse, os, signal, multiprocessing, subprocess
from utils.procManager import ProcManager
from utils.testbench import Testbench
from utils.utility import *
from scapy.all import sniff



def sniff_packets(cmd_q, testbench):
    """ 
    waiting interface ready
    """
    while True:
        try:
            result = subprocess.run(
                ["ip", "link", "show", testbench.simulator_interface], capture_output=True, text=True
            ).stdout
            if "UP" in result:
                print(f"[+] Interface {testbench.simulator_interface} UP")
                break
        except Exception as e:
            print("[!]Error checking interface: ", e)
            continue

    print("[+] Sniffing for packets...", flush=True)
    try:
        packets = sniff(iface=testbench.simulator_interface,
                    filter="sctp port 38412",
                    prn=lambda packet: testbench.qpkt.put(packet),
                    store=False)    
    except OSError as e:
        print(f"[!] Interface seems to be down: {e}")
        cmd_q.put("restart sniff_packets")
    return 
    
if __name__ == "__main__":
    logo = """ 
     @@@@@@    @@@@@@@   @@@@@@    @@@@@@    @@@@@@@   @@@@@@   @@@  @@@                   @@@@@@@   @@@@@@@@  
    @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@                   @@@@@@@  @@@@@@@@@  
    !@@       !@@       @@!  @@@  !@@       !@@       @@!  @@@  @@!@!@@@                   !@@      !@@        
    !@!       !@!       !@!  @!@  !@!       !@!       !@!  @!@  !@!!@!@!                   !@!      !@!        
    !!@@!!    !@!       @!@!@!@!  !!@@!!    !@!       @!@!@!@!  @!@ !!@!     @!@!@!@!@     !!@@!!   !@! @!@!@  
     !!@!!!   !!!       !!!@!!!!   !!@!!!   !!!       !!!@!!!!  !@!  !!!     !!!@!@!!!     @!!@!!!  !!! !!@!!  
         !:!  :!!       !!:  !!!       !:!  :!!       !!:  !!!  !!:  !!!                       !:!  :!!   !!: 
        !:!   :!:       :!:  !:!      !:!   :!:       :!:  !:!  :!:  !:!                       !:!  :!:   !::
    :::: ::    ::: :::  ::   :::  :::: ::    ::: :::  ::   :::   ::   ::                   :::: ::   ::: ::::  
    :: : :     :: :: :   :   : :  :: : :     :: :: :   :   : :  ::    :                    :: : :    :: :: :  
    """
    # Parse arguments
    print(logo)
    argparser = argparse.ArgumentParser(description= "SCAScan-5G, a Framework for 5G Vulnerability Assessment following 3GPP SCAS TSs.")

    argparser.add_argument("--path", type=str, dest="path", help="5g core simulatore path")
    argparser.add_argument("--test",type=str, dest="test", help="Select test case, default 'ANY'. Comma separated values and range values supported . --tests-enum lists available tests", default=-1)
    argparser.add_argument("--test-enum", action="store_true", help="Show every test available")
    arg = argparser.parse_args()
    
    if arg.test_enum:
        argparser.print_help()
        print("\nAvailable tests:")
        for key, test in Testbench.available_tests.items():
            print(f"[>>] {key}: {test['name']}")
        exit(0)

    testbench = Testbench(arg.test, arg.path)
    print("[+] SCAScan-5G Testbench initialized", flush=True)
    print(f"[+] Using 5G Core Simulator at {testbench.simulator_path}", flush=True)
    print(f"[+] Using 5G Core Simulator interface {testbench.simulator_interface}", flush=True)
    print(f"[+] Selected tests: "
            f"{', '.join(testbench.available_tests[t]['name'] for t in testbench.tests)}", flush=True)
    pManager = ProcManager()
    signal.signal(signal.SIGINT, lambda signal, frame: testbench.graceful_shutdown(pManager.cmd_q))

    #Create testCase<->Controller pipe
    server_pipe, client_pipe = multiprocessing.Pipe()

    try:
        pManager.run_process(testbench.manage_core_simulator)
        pManager.run_process(sniff_packets, testbench)
        pManager.wait_process(testbench.manage_core_simulator)

        pManager.run_process(testbench.pktparser)
        pManager.run_process(ctrl, server_pipe)
        for test in testbench.tests:
            fun = getattr(testbench, testbench.available_tests[test]['name'], None)
            if callable(fun):
                print("---------------------------")
                pManager.run_process(fun, (client_pipe))
                pManager.wait_process(fun)
                print(f"[+] {fun.__name__} {'Passed' if testbench.result[fun.__name__] else 'Failed'}")
                print("---------------------------")
            else:
                print(f"[!] Test case {testbench.available_tests[test]['name']} is not callable or does not exist.")
                exit(1)

    
    except Exception as e:
        print(f"[!] Error: {e}")
        testbench.graceful_shutdown(pManager.cmd_q)
        exit(1)
    
    print("///////// RESULTS \\\\\\\\\\\\\\\\\\")
    for test,result in testbench.result.items():
        print(f"[//] {test} -> {result}")
    testbench.graceful_shutdown(pManager.cmd_q)
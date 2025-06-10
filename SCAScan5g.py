import logging, argparse, signal, multiprocessing, subprocess
from utils.procManager import ProcManager
from utils.testbench import Testbench
from utils.controller import *
from utils.logger import setup_logger
from scapy.all import sniff


logger = logging.getLogger("SCAScan5g")

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
                logger.info(f"Interface {testbench.simulator_interface} UP")
                break
        except Exception as e:
            logger.warning("Error checking interface: ", e)
            continue

    logger.info("Sniffing for packets...")
    try:
        #Sniffing SCTP ONLY - for future works, consider rearrenge or modify the filter to enable more flexibility
        packets = sniff(iface=testbench.simulator_interface,
                    filter="sctp port 38412",
                    prn=lambda packet: testbench.qpkt.put(packet),
                    store=False)    
    except OSError as e:
        logging.warning(f"[!] Interface seems to be down: {e}")
        cmd_q.put(("restart", "sniff_packets"))
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
    argparser = argparse.ArgumentParser(description= "SCAScan-5G, a Framework for 5G Vulnerability Assessment following 3GPP SCAS TSs.")

    argparser.add_argument("--path", type=str, dest="path", help="5g core simulatore path")
    argparser.add_argument("--test",type=str, dest="test", help="Select test case, default 'ANY'. Comma separated values and range values supported . --tests-enum lists available tests", default=-1)
    argparser.add_argument("--test-enum", action="store_true", help="Show every test available")
    argparser.add_argument("-v", "--verbose", action="store_true", help="Set verbose logging")
    argparser.add_argument("--dump", type=str, dest="log_file", help="Save Logs into log_file")
    
    arg = argparser.parse_args()
    
    setup_logger(verbose=arg.verbose,log_file=arg.log_file)
    plain_logger = logging.getLogger("plain")
    plain_logger.info(logo)
    if arg.test_enum:
        argparser.print_help()
        print("\nAvailable tests:")
        for key, test in Testbench.available_tests.items():
            print(f"[>>] {key}: {test['name']}")
        exit(0)

    testbench = Testbench(arg.test, arg.path)
    logger.info("SCAScan-5G Testbench initialized")
    logger.info(f"Using 5G Core Simulator at {testbench.simulator_path}")
    logger.info(f"Using 5G Core Simulator interface {testbench.simulator_interface}")
    logger.info(f"Selected tests: "
            f"{', '.join(testbench.available_tests[t]['name'] for t in testbench.tests)}")
    pManager = ProcManager()
    signal.signal(signal.SIGINT, lambda signal, frame: testbench.graceful_shutdown(pManager.cmd_q))

    #Create testCase<->Controller pipe
    server_pipe, client_pipe = multiprocessing.Pipe()

    try:
        pManager.run_process(testbench.manage_core_simulator)
        pManager.run_process(sniff_packets, testbench)
        pManager.wait_process(testbench.manage_core_simulator)
        pManager.run_process(testbench.pktparser)
        pManager.run_process(ctrl, (testbench.simulator_proxy_ip, testbench.simulator_proxy_port, server_pipe))
        for test in testbench.tests:
            fun = getattr(testbench, testbench.available_tests[test]['name'], None)
            if callable(fun):
                plain_logger.info("-----------------------------------------------")
                pManager.run_process(fun, (client_pipe))
                pManager.wait_process(fun)
                logger.info(f"{fun.__name__} {'Passed' if testbench.result[fun.__name__] else 'Failed'}")
                plain_logger.info("-----------------------------------------------")
            else:
                logger.error(f"[!] Test case {testbench.available_tests[test]['name']} is not callable or does not exist.")
                exit(1)
    except Exception as e:
        logger.error(f"[!] Error: {e}")
        testbench.graceful_shutdown(pManager.cmd_q)
        exit(1)
    plain_logger.info("------------------/ RESULTS \\------------------")
    plain_logger.info("-----------------------------------------------")
    for test,result in testbench.result.items():
        plain_logger.info(f"| {test} | {'Passed' if result else 'Failed'}")
    plain_logger.info("-----------------------------------------------")
    testbench.graceful_shutdown(pManager.cmd_q)
import socket, json, logging


def ctrl(cmq_q, ip , port , pipe):
    """ Function handling control connection with the proxy"""
    """ Receives data from the testCase function through the pipe
        and sends it to the proxy through the socket """
    logger = logging.getLogger(__name__)
    sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sckt.connect((ip, port))
    logger.info(f"Control connection established with {ip}:{port}")

    while True:
        if pipe.poll():
            """ Expected data is dict = {'testCase': tc_name, 'msg': msg} """

            data = pipe.recv()
            logger.info(f" Received data from test case")
            
            """ Exit condition """
            if data == "exit":
                logger.info(" Exiting control connection")
                sckt.close()
                break

            data = json.dumps(data).encode()

            sckt.sendall(data) 
            logger.info(f" Sent data to proxy")
            sckt.settimeout(5)
            try:
                resp = sckt.recv(1024).decode('utf-8').strip()
            except socket.timeout:
                logger.info(" Timeout waiting for response from proxy")
            if resp == "Test OK":
                logger.info(f" Test case executed successfully")
                pipe.send("Test OK")
            elif resp == "Test KO":
                logger.info(f" Test case execution failed")
                pipe.send("Test KO")  
            elif not resp:
                logger.info(" Control connection closed by proxy")
                sckt.close()
                break
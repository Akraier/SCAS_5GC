import socket, json


def ctrl(cmq_q, ip , port , pipe):
    """ Function handling control connection with the proxy"""
    """ Receives data from the testCase function through the pipe
        and sends it to the proxy through the socket """
    
    sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sckt.connect((ip, port))
    print(f"[+] Control connection established with {ip}:{port}", flush=True)

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
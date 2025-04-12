import sctp 
import socket
import threading
import traceback
import json
from MyNGAPdissector import NAS, NGAP 

CTRL_PORT = 1337
GNB_PORT = 38412
AMF_PORT = 38412
AMF_HOST = "amf.free5gc.org"

active_conns = {}

tests= ["tc_amf_nas_integrity_failure", "tc_nas_replay_amf"]

def amf_nas_integrity(amf_conn):
    """Craft a NAS message with tampered MAC Address"""

def nas_replay_amf(amf_conn):
    """Replay Security Mode Command message"""

def forward(src_sock, dst_sock, direction):
    print(f"[+] Forwarding {direction}", flush=True)
    ppid = socket.htonl(60)
    while True:
        try:
            data = src_sock.sctp_recv(4096)
            if not data:
                print(f"[!] connection closed" + direction, flush=True)
                break
            dst_sock.sctp_send(data[2], ppid=ppid)
        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()
            break

def handle_client(gnb_conn):
    ip, port = gnb_conn.getpeername()
    print(f"[+]gNB Connected {ip}:{port}", flush=True)

    amf_conn = sctp.sctpsocket_tcp(socket.AF_INET)
    amf_conn.connect((AMF_HOST,AMF_PORT))
    amf_ip, amf_port = amf_conn.getpeername()
    print(f"[+]Connected to AMF {amf_ip}:{amf_port}", flush=True)

    active_conns['gnb'] = gnb_conn
    active_conns['amf'] = amf_conn

    threading.Thread(target=forward, args=(gnb_conn, amf_conn, "gNB -> AMF")).start()
    threading.Thread(target=forward, args=(amf_conn, gnb_conn, "AMF -> gNB")).start()

def control_server():
    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl_sock.bind(('0.0.0.0',CTRL_PORT))
    ctrl_sock.listen(1)
    print(f"[+] Control server listening on port {CTRL_PORT}", flush=True)

    while True:
        conn, _ = ctrl_sock.accept()
        data = conn.recv(4096).decode().strip()
        try:
            msg = json.loads(data)
            print("[CTRL] Received JSON:", msg, flush=True)
            if msg["testCase"] not in tests:
                print(f"[!] Unknown test case: {msg['testCase']}", flush=True)
                conn.send(b"Unknown test case\n")
                continue
            if msg["testCase"] == "tc_amf_nas_integrity_failure":
                print("[CTRL] Test case: tc_amf_nas_integrity_failure", flush=True)
                amf_nas_integrity(active_conns['amf'])
                conn.send(b"Test case OK\n")
            elif msg["testCase"] == "tc_nas_replay_amf":
                print("[CTRL] Test case: tc_nas_replay_amf", flush=True)
                nas_replay_amf(active_conns['amf'])
                conn.send(b"Test case OK\n")
        except json.JSONDecodeError:
            print(f"[!] Invalid JSON format: {data}", flush=True)
            conn.send(b"Invalid JSON format\n")
            conn.close()
            continue

        conn.send(b"OK\n")
        conn.close()

def main():
    """ Server waiting for gNB connections"""

    listener = sctp.sctpsocket_tcp(socket.AF_INET)
    listener.bind(('',GNB_PORT))
    listener.listen(5)

    print(f"[+] Listening on SCTP port {GNB_PORT}", flush=True)

    while True:
        gnb_conn, _ = listener.accept()
        threading.Thread(target=handle_client, args=(gnb_conn,)).start()

if __name__ == "__main__":
    threading.Thread(target=control_server, daemon=True).start()
    main()
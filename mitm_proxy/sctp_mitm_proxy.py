import sctp, socket, threading, traceback, json, os, logging, sys

CTRL_PORT = int(os.environ.get("CTRL_PORT"))
GNB_PORT = int(os.environ.get("GNB_PORT"))
AMF_PORT = int(os.environ.get("AMF_PORT"))
AMF_HOST = os.environ.get("AMF_HOST")


logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Avoid duplicate handlers
if not logger.hasHandlers():
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter('[%(levelname)s] | %(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

active_conns = {}

tests= ["tc_amf_nas_integrity_failure", "tc_nas_replay_amf", "tc_ue_sec_cap_handling_amf"]

def forward(src_sock, dst_sock, direction):
    logger.info(f" Forwarding {direction}")
    ppid = socket.htonl(60)
    while True:
        try:
            data = src_sock.sctp_recv(4096)
            if not data:
                logger.info(f"[!] connection closed" + direction)
                break
            dst_sock.sctp_send(data[2], ppid=ppid)
        except Exception as e:
            logger.exception(f"Error")
            break

def handle_client(gnb_conn):
    ip, port = gnb_conn.getpeername()
    logger.info(f"gNB Connected {ip}:{port}")

    amf_conn = sctp.sctpsocket_tcp(socket.AF_INET)
    amf_conn.connect((AMF_HOST,AMF_PORT))
    amf_ip, amf_port = amf_conn.getpeername()
    logger.info(f"Connected to AMF {amf_ip}:{amf_port}")

    active_conns['gnb'] = gnb_conn
    active_conns['amf'] = amf_conn

    threading.Thread(target=forward, args=(gnb_conn, amf_conn, "gNB -> AMF")).start()
    threading.Thread(target=forward, args=(amf_conn, gnb_conn, "AMF -> gNB")).start()

def inject_msg(conn, target, msg):
    logger.info(f" Test case: {msg['testCase']} STARTED")
    logger.info(f" Trying to inject {bytes.fromhex(msg['msg'])}")

    active_conns[target].sctp_send(bytes.fromhex(msg['msg']), ppid=socket.htonl(60))

    logger.info(f" {msg['testCase']} injected")
    conn.sendall(b"Test OK\n")
    logger.info(f" Test case: {msg['testCase']} FINISHED")

def control_server():
    ctrl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctrl_sock.bind(('0.0.0.0',CTRL_PORT))
    ctrl_sock.listen(1)
    logger.info(f" Control server listening on port {CTRL_PORT}")

    ppid = socket.htonl(60)
    
    while True:
        conn, addr = ctrl_sock.accept()
        logger.info(f" Control connection accepted {addr}")

        while True:
            try:
                data = conn.recv(4096).decode('utf-8').strip()
                msg = json.loads(data)
                logger.info("[CTRL] Received JSON:", msg)
                if msg["testCase"] not in tests:
                    logger.error(f"[!] Unknown test case: {msg['testCase']}")
                    conn.sendall(b"Test KO\n")
                    continue
                elif not msg:
                    logger.info("[CTRL] Control Connection closed")
                    conn.close()
                    return
                else:
                    inject_msg(conn, 'amf', msg)
                    continue
            except json.JSONDecodeError:
                logger.exception(f"[!] Invalid JSON format")
                conn.send(b"Test KO\n")
                conn.close()
                continue
            except Exception as e:
                logger.exception(f"[!] Error")
                conn.send(b"Test KO\n")
                conn.close()
        conn.close()


def main():
    """ Server waiting for gNB connections"""

    listener = sctp.sctpsocket_tcp(socket.AF_INET)
    listener.bind(('',GNB_PORT))
    listener.listen(5)
    logger.info(f" AMF_IP {AMF_HOST}")
    logger.info(f" Listening on SCTP port {GNB_PORT}")

    while True:
        gnb_conn, _ = listener.accept()
        threading.Thread(target=handle_client, args=(gnb_conn,)).start()

if __name__ == "__main__":
    threading.Thread(target=control_server, daemon=True).start()
    
    main()
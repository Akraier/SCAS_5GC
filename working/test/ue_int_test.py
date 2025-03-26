import subprocess
import json
import traceback
import asn1tools
from MyNGAPdissector import *

def interaction(command):
    retrieve_UEs = """./nr-cli -d"""
    if command not in {"info","status","timers","coverage","ps-establish","ps-list","ps-release","ps-release-all","deregister"}:
        print("[!]Invalid command")
        return None
    try:
        
        output = subprocess.run(["docker", "exec", "-it", "ue", "/bin/sh", "-c", retrieve_UEs], capture_output=True, text=True)
        print("captured output(imsi):"+output.stdout)
        imsi = output.stdout.strip()
        print("imsi:"+imsi)
        run_command = f"""./nr-cli {imsi} --exec {command}"""
        print("run_command:"+run_command)
        output = subprocess.run(["docker", "exec", "-it", "ue", "/bin/sh", "-c", run_command], capture_output=True, text=True)
        return output.stdout.strip()
    except Exception as e:
        print("[!]Error interacting with UERANSIM UE shell: ", e)
        return None
def extract_deregistration():
    #open hex_dereg_req.json file
    try:
        with open("hex_dereg_req.json") as f:
            data = json.load(f)
            print(bytes.fromhex(data["ngap"]))
            segment = NGAP()
            segment.dissect_ngap_pdu(bytes.fromhex(data["ngap"]))
            segment.print_ngap()
            print(type(segment))
            print("SEGMENT OK")
            #re-serialization
            raw = segment.build_ngap_pdu(segment.segment)
            print(raw.hex())
            if segment.segment["Initiating Message"]["raw"] == raw.hex():
                print("BINGO")
            if raw.hex() == data["ngap"]:
                print("ESAGERATO")
             
    except Exception as e:
        print("[!]Error extracting deregistration request: ")
        traceback.print_exc()
        return None
def test_asn1():
    ngap_compiler = asn1tools.compile_files('ngap.asn')
    with open("hex_dereg_req.json") as f:
        data = json.load(f)
        print(bytes.fromhex(data["ngap"]))
        segment = NGAP(bytes.fromhex(data["ngap"]))
    decoded = ngap_compiler.decode('NGAP-PDU', segment)
extract_deregistration()
#print()
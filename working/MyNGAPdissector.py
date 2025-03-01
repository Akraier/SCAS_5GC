from utilities import *

### My NGAP Dissector ###
# This script will take in a NGAP payload and dissect it into IEs
# The IEs will be stored in a dictionary and returned
class NGAP:
    def __init__(self, raw_segment):
        self.ngap_segment = self.dissect_ngap_pdu(raw_segment)

    def dissect_ngap_ie(self, raw_segment):
        #takes in input ngap value payload and dissects it in IEs
        #return a dictionary of IEs {id: {IE_criticality, IE_length, IE_value}, ...}

        try:
            if raw_segment is None or len(raw_segment) < 4:
                print("[!]Empty NGAP value")
                return None
            protocol_ies = int.from_bytes(raw_segment[:3], byteorder='big')   #4 bytes
            raw_segment = raw_segment[3:]
            ie = {}
            print(f"[DEBUG] Protocol IEs: {protocol_ies}")
            for i in range(protocol_ies):
                #IE_id = int.from_bytes(raw_segment[:2],byteorder='big')     #IE id, 2 bytes
                IE_id = raw_segment[:2]
                IE_criticality = (raw_segment[2] & 0b11000000) >> 6  #IE criticality, 2 bits
                IE_length = raw_segment[3]   #IE length, 1 byte
                IE_value = raw_segment[4:4+IE_length]    #IE value, variable length
                raw_segment = raw_segment[4+IE_length:]   #update ngap value

                #update dictionary
                ie[IE_id] = {"IE_criticality": IE_criticality, "IE_length": IE_length, "IE_value": IE_value}
                #print(f"[DEBUG] IE building : {ie}")
            #print(f"[DEBUG] IE completed: {ie}")
            return ie

        except Exception as e:
            print("[!]Error dissecting ngap ie:", e)
            return None

    def dissect_ngap_pdu(self, chunk_data):
        try:
            ngap = {}
            first_byte = chunk_data[0]
            pdu_type = (first_byte & 0b11110000) >> 4
            reserved = first_byte & 0b00001111
            procedure_code = chunk_data[1]
            criticality = (chunk_data[2] & 0b11000000) >> 6
            value_length = chunk_data[3]
            value = chunk_data[4:4+value_length]
            """ print(f"[DEBUG] First Byte: {first_byte}")
            print(f"[DEBUG] Reserved: {reserved}")
            print(f"[DEBUG] PDU Type: {pdu_type}")
            print(f"[DEBUG] Procedure Code: {procedure_code}")
            print(f"[DEBUG] Criticality: {criticality}") 
            print(f"[DEBUG] Value Length: {value_length}")
            print(f"[DEBUG] Value: {value.hex()}")"""
            IEs = self.dissect_ngap_ie(value)    #
            if IEs is None:
                print("[-] Error dissecting IEs")
                return
            #print(f"[+] Dissected IEs: {IEs}")
            ngap[pdu_type] = {"procedure_code": procedure_code, "criticality": criticality, "value_length": value_length, "IEs": IEs}
            return ngap
        except Exception as e:
            print("[!]Error dissecting ngap:", e)
            return
        
    def print_ngap(ngap):
        try:
            print("[>>] Print NGAP PDU")
            for pdu_type, pdu_details in ngap.items():
                print(f"\t[>>] PDU Type: {pdu_type}")
                print(f"\t[>>] Procedure Code: {pdu_details['procedure_code']}")
                print(f"\t[>>] Criticality: {pdu_details['criticality']}")
                print(f"\t[>>] Value Length: {pdu_details['value_length']}")
                IEs = pdu_details['IEs']
                for IE_id, IE in IEs.items():
                    print(f"\t[>>] IE ID: {IE_id.hex()}")
                    print(f"\t\t[>>] IE Criticality: {IE['IE_criticality']}")
                    print(f"\t\t[>>] IE Length: {IE['IE_length']}")
                    print(f"\t\t[>>] IE Value: {IE['IE_value'].hex()}")
            return
        except Exception as e:
            print("[!]Error printing ngap:", e)
            return
        
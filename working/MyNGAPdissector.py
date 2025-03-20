from utilities import *
import json
import traceback

id_NAS_PDU = 38
MM_epd = 126
SM_epd = 46
### My NAS Class ###
#class myPacket:


class NAS:
    epd_enum = {
        46: "Session Management Message",
        126: "Mobility Management Message"
    }
    sht_enum = {
        0:"PlainNAS",
        1:"Integrity",
        2:"Integrity + Encryption",
        3:"Integrity by 5GNAS Security Context",
        4:"Integrity + Encryption by 5GNAS Security Context"
    }
    

    """def __init__(self,raw_data):
        self.dissect_nas_pdu(raw_data) """
    
    def build_plain_nas_pdu(self,pdu):
        #construct raw binary data from pdu dictionary
        #SERIALIZATION FUNCTION
        try:
            #Reverse lookup for epd and sht values
            epd = self.reverse_epd_enum[pdu["epd"]]
            sht = self.reverse_sht_enum[pdu["sht"]]

            #EPD
            epd_byte = bytes([epd])
            #SHT
            sht_byte = (0x00 << 4) | (sht & 0x0F)   #0x00 Spare Half Octet 
            sht_byte = bytes([sht_byte])
            #message type & value
            message_type = self.reverse_message_type_dict[pdu["message_type"]]
            message_value = bytes.fromhex(pdu["message_value"])

            payload = b""

            if epd == self.reverse_epd_enum["Session Management Message"]:
                #Session Management message, PTI present
                pti = pdu["pti"] if pdu["pti"] != "None" else 0x00
                payload += bytes([pti])
                payload += bytes([message_type])
            elif epd == self.reverse_epd_enum["Mobility Management Message"]:
                #PTI optional
                if message_type in [12,13,14]:
                    #PTI not present
                    payload += bytes([message_type])
                else:
                    #PTI present
                    pti = pdu["pti"] if pdu["pti"] != "None" else 0x00
                    payload += bytes([pti])
                    payload += bytes([message_type])
            else:
                print("[!]Unknown EPD")
                return None
            
            payload += message_value
            nas_pdu = epd_byte + sht_byte + payload
            return nas_pdu
        except Exception as e:
            print("[!]Error building plain NAS PDU:")
            traceback.print_exc()
            return None

    def build_nas_pdu(self,pdu):
        #SERIALIZATION FUNCTION
        """ input type {SecurityProtectedNASPDU":{"epd":..,"sht":..},"PlainNASPDU":{}}} """
        reverse_epd_enum = {v: k for k, v in self.epd_enum.items()}
        reverse_sht_enum = {v: k for k, v in self.sht_enum.items()}
        reverse_message_type_dict = {v: k for k, v in message_type_dict.items()}
        if "SecurityProtectedNASPDU" not in pdu.keys():
            return self.build_plain_nas_pdu(pdu["PlainNASPDU"])
        
        raw = b""
        sec_pdu = pdu["SecurityProtectedNASPDU"]
        plain_pdu = pdu["PlainNASPDU"]

        epd = self.reverse_epd_enum[sec_pdu["epd"]]
        sht = self.reverse_sht_enum[sec_pdu["sht"]]
        mac = bytes.fromhex(sec_pdu["mac"])
        seq_no = sec_pdu["seq_no"]
        enc_msg = self.build_plain_nas_pdu(plain_pdu)
        
        epd_byte = epd.to_bytes(1, byteorder='big')
        sht_byte = sht.to_bytes(1, byteorder='big')   #review
        seq_no_byte = seq_no.to_bytes(1, byteorder='big')
        raw = epd_byte + sht_byte + mac + seq_no_byte + enc_msg
        print("[DEBUG] serialized nas pdu", raw.hex())
        return raw


    def dissect_plain_nas_pdu(self, raw, epd, sht):
        try:
            if len(raw) < 2:
                #only message_type, just for specific messages [Registration Complete]
                message_type = raw[0]
                message_value = bytes(0)
                pti = None
            elif epd == SM_epd:
                #Session Management message, PTI present
                print("[DEBUG] Session Management Message")
                pti = raw[0]
                message_type = raw[1]
                message_value = raw[2:]
                
            elif epd == MM_epd:
                #Mobility Management message, PTI Optional
                #assume pti present
                print("[DEBUG] Mobility Management Message")
                pti = raw[0]
                message_type = raw[1]
                message_value = raw[2:]
                print(f"[DEBUG] Message Type: {message_type}")
                #pti should be present only in the following MM message types
                if (message_type != 12) and (message_type != 13) and (message_type != 14):
                    #pti not present, erase previous values
                    pti = "None"
                    message_type = raw[0]
                    message_value = raw[1:]
                #print(f"[DEBUG] Message Type: {hex(message_type)}")
                
            #pdu unencrypted
            pdu = {
                "epd":self.epd_enum[epd],
                "sht":self.sht_enum[sht],
                "pti":pti, #None if non-exhistent
                "message_type": message_type_dict[message_type],
                "message_value": message_value.hex()
            }
            
            return pdu
        except Exception as e:
            print("[!]Error dissecting plain NAS PDU:")
            traceback.print_exc()
            return None

    def dissect_nas_pdu(self,raw):
        pdu = {}
        pti = -1
        message_type = 0
        message_value = 0
        mac = 0
        seq_no = 0
        enc_msg = 0

        try:
            length = raw[0] 
            epd = raw[1] 
            """ if epd != MM_epd and epd != SM_epd:
                #id-NAS-PDU can have additional byte before epd because of NGAP
                #stripped it off for simplicity
                print("[DEBUG] Additional byte before epd")
                epd = raw[1]
                raw = raw[1:] """

            sht = raw[2] & 0x0F    #SHT is lower nibble bits 0-3
            print(f"[DEBUG] Raw NAS PDU: {raw.hex()}")
            print(f"[DEBUG] Length: {length}")
            print(f"[DEBUG] epd value: {epd}")
            print(f"[DEBUG] sht value: {sht}")
            if sht == 0:
                #plain NAS PDU
                print("[DEBUG] Plain NAS PDU")
                pdu = self.dissect_plain_nas_pdu(raw[3:], epd, sht)
                if pdu != None:
                    self.pdu = {"PlainNASPDU":pdu}
                    return 1
                
            elif sht != 0:
                #security protected PDU headers
                mac = raw[3:7]
                seq_no = raw[7]
                enc_msg = raw[8:]
                #headers of plain nas pdu integrity/cipher protected
                epd_enc = enc_msg[0]
                sht_enc = enc_msg[1] & 0x0F
                pdu_enc = enc_msg[2:]
                print(f"[DEBUG] MAC : {mac.hex()}")
                print(f"[DEBUG] Seq.No: {seq_no}")
                print(f"[DEBUG]EPD_ENC: {epd_enc}")
                print(f"[DEBUG]SHT_ENC: {sht_enc}")
                print(f"[DEBUG]PDU_END: {pdu_enc.hex()}")

                plain_pdu = self.dissect_plain_nas_pdu(pdu_enc, epd_enc, sht_enc)
                if plain_pdu is None:
                    print("[-] Error dissecting plain PDU")
                    return None
                pdu = {
                    "SecurityProtectedNASPDU":{
                        "epd":self.epd_enum[epd],
                        "sht":self.sht_enum[sht],
                        "mac":mac.hex(), 
                        "seq_no": seq_no
                    },
                    "PlainNASPDU": plain_pdu,
                }
                self.pdu = pdu
                return 1
        except Exception as e:
            print("[!]Error dissecting NAS PDU:")
            traceback.print_exc()
            return None


### My NGAP Dissector ###
# This class will build NGAP frames

class NGAP:
    pdu_type_values = { 
        0: "Initiating Message",
        2: "Successful Outcome",
        1: "Unsuccessful Outcome"
    }

    """ def __init__(self, raw_segment):
        self.segment = self.dissect_ngap_pdu(raw_segment)
        #print("[!] TYPE OF SEGMENT:", type(self.segment))
        if self.segment != None:
            self.print_ngap(self.segment)
        else:
            print("[!] Error dissecting NGAP") """
    def build__ngap_ie(self, ie_dict):
        #IE SERIALIZATION
        #input IEs dictionary {"id-ie1":"","id-ie2":"",..} -- ie_dict should be dict["IEs"]
        try:
            reverse_ngap_ie_dict = {v: k for k, v in ngap_ie_dict.items()}
            #first 3 bytes are the number of IEs in the protocol
            protocol_ies = len(ie_dict)
            protocol_ies_bytes = protocol_ies.to_bytes(3, byteorder='big')
            raw = b""
            for ie_id, ie_value in ie_dict.items():
                if ie_id not in reverse_ngap_ie_dict:
                    print(f"[!] Unknown IE ID: {ie_id}")
                    return None
                IE_id_ = reverse_ngap_ie_dict[ie_id]
                IE_id_bytes = IE_id_.to_bytes(2, byteorder='big')
                raw += IE_id_bytes
                IE_criticality = ie_value["IE_criticality"]
                IE_criticality_bytes = (IE_criticality << 6) & 0b11000000
                raw += IE_criticality_bytes
                IE_length = ie_value.get["IE_length"]
                IE_length_bytes = IE_length.to_bytes(1, byteorder='big')
                raw += IE_length_bytes
                #head_bytes = IE_id_bytes + IE_criticality_bytes + IE_length_bytes
                #NAS PDU handling
                if ie_id == "id-NAS-PDU":
                    nas_pdu = ie_value.get("NAS PDU")
                    nas = NAS()
                    nas_pdu_raw = nas.build_nas_pdu(nas_pdu)
                    if nas_pdu_raw is None:
                        print("[-] Error building NAS PDU")
                        return None
                    raw += nas_pdu_raw
                else:
                    IE_value = ie_value["IE_value"]
                    IE_value_bytes = bytes.fromhex(IE_value)
                    raw += IE_value_bytes
            return raw
        except Exception as e:
            print("[!]Error building NGAP IEs:")
            traceback.print_exc()
            return None

    def build_ngap_pdu(self, ngap_dict):
        try:
            reverse_pdu_type_values = {v: k for k, v in self.pdu_type_values.items()}
            #NGAP message type
            ngap_msg_type = next(iter(ngap_dict))
            pdu_data = ngap_dict[ngap_msg_type]
            #first byte is pdu type MSB & reserved bytes LSB
            pdu_type = reverse_pdu_type_values[ngap_msg_type]
            first_byte = (pdu_type << 4) & 0b11110000
            pdu += first_byte

            procedure_code = pdu_data["procedure_code"]
            second_byte = procedure_code.to_bytes(1, byteorder='big')
            pdu += second_byte
            #third byte is criticality in the first 2 bits of the MS Byte
            criticality = pdu_data["criticality"]
            third_byte = (criticality << 6) & 0b11000000
            pdu += third_byte

            #length of the value following (ARBITRARY) BER encoding
            length = pdu_data["value_length"]
            if length < 127:
                length_byte = length.to_bytes(1, byteorder='big')
            else:
                #0x80 + 1 byte length
                msb = 0x80
                length_byte = (0x80 << 8) | length.to_bytes(1, byteorder='big')
            pdu += length_byte

            #IEs serialization
            ies_dict = pdu_data["IEs"]
            IEs = self.build__ngap_ie(ies_dict)
            if IEs is None:
                print("[-] Error building IEs")
                return None
            ret = first_byte + second_byte + third_byte + length_byte + IEs
            
            #padding
            if len(IEs) < length:
                print("[DEBUG] Padding")
                padding = length - len(IEs)
                return  ret + b'\x00' * padding
            
            return ret

        except Exception as e:
            print("[!]Error building NGAP PDU:")
            traceback.print_exc()
            return None
    
    def dissect_ngap_ie(self, raw_segment):
        #takes in input ngap value payload and dissects it in IEs
        #return a dictionary of IEs {id: {IE_criticality, IE_length, IE_value}, ...}

        try:
            if raw_segment is None or len(raw_segment) < 4:
                print("[!]Empty NGAP value")
                return None
            protocol_ies = int.from_bytes(raw_segment[:3], byteorder='big')   #3 bytes
            #raw_segment = raw_segment[3:]
            ie = {}
            #print(f"[DEBUG] Protocol IEs: {protocol_ies}")
            raw_segment = raw_segment[3:]   #update ngap value
            for i in range(protocol_ies):
                #print(f"[DEBUG] Remaining IEs: {raw_segment.hex()}")
                #IE_id = int.from_bytes(raw_segment[:2],byteorder='big')     #IE id, 2 bytes
                IE_id = int.from_bytes(raw_segment[:2],byteorder='big')     #IE id, 2 bytes
                IE_criticality = (raw_segment[2] & 0b11000000) >> 6  #IE criticality, 2 bits
                IE_length = raw_segment[3]   #IE length, 1 byte
                IE_value = raw_segment[4:4+IE_length]    #IE value, variable length
                #print(f"[DEBUG] IE ID: {IE_id}")
                if IE_id == id_NAS_PDU:
                    #print("[DEBUG] Dissecting NAS PDU")
                    #dissect NAS PDU
                    nas = NAS()
                    if not nas.dissect_nas_pdu(IE_value):
                        print("[-] Error dissecting NAS PDU")
                        return None
                    else:
                        ie[ngap_ie_dict[IE_id]] = {"IE_criticality": IE_criticality, "IE_length": IE_length, "NAS PDU": nas.pdu}
                #update dictionary
                elif IE_id in ngap_ie_dict and IE_id != id_NAS_PDU:
                    ie[ngap_ie_dict[IE_id]] = {"IE_criticality": IE_criticality, "IE_length": IE_length, "IE_value": IE_value.hex()}
                elif IE_id not in ngap_ie_dict:
                    #Atypical case, NGAP length is bigger than 217 bytes,
                    print(f"[DEBUG] Atypical Segment: {raw_segment.hex()}")
                    self.dissect_ngap_ie(raw_segment[2:])
                    ie[ngap_ie_dict[IE_id]] = {"IE_criticality": IE_criticality, "IE_length": IE_length, "IE_value": IE_value.hex()}
                    break
                
                #print(f"[DEBUG] IE building : {ie}")
                raw_segment = raw_segment[4+IE_length:]   #update ngap value

            #print(f"[DEBUG] IE completed: {ie}")
            return ie

        except Exception as e:
            print("[!]Error dissecting ngap ie:")
            traceback.print_exc()
            return None

    def dissect_ngap_pdu(self, chunk_data):
        #Dissect SCTP Chunk data in NGAP PDU frame
        try:
            ngap = {}
            first_byte = chunk_data[0]
            pdu_type = (first_byte & 0b11110000) >> 4
            reserved = first_byte & 0b00001111
            procedure_code = chunk_data[1]
            criticality = (chunk_data[2] & 0b11000000) >> 6
            #ASN1 BER length Encoding. Following Length extraction could be prone to error for high length packets
            #ASN1 encoding is not clear for free5gc and probably broken  CVE-2022-43677. 
            #0x80 + 1 byte length used for length > 127
            if len(chunk_data) <= 127:
                value_length = chunk_data[3]
                value = chunk_data[4:4+value_length]

            else:
                value_length = chunk_data[4]
                value = chunk_data[5:5+value_length]
            """ print(f"[DEBUG] First Byte: {first_byte}")
            print(f"[DEBUG] Reserved: {reserved}")
            print(f"[DEBUG] PDU Type: {pdu_type}")
            print(f"[DEBUG] Procedure Code: {procedure_code}")
            print(f"[DEBUG] Criticality: {criticality}") 
            print(f"[DEBUG] Value Length: {value_length}")
            print(f"[DEBUG] Value: {value.hex()}")"""
            IEs = self.dissect_ngap_ie(value)    #returns a dictionary containing all IEs in the packet
            if IEs is None:
                print("[-] Error dissecting IEs")
                return 0
            #print(f"[+] Dissected IEs: {IEs}")
            ngap[self.pdu_type_values[pdu_type]] = {"procedure_code": procedure_code, "criticality": criticality, "value_length": value_length, "IEs": IEs, "raw": chunk_data.hex()}
            self.segment = ngap
            return 1 
        except Exception as e:
            print("[!]Error dissecting ngap:", e)
            return 0
        
    def get_nas_pdu(self):
        #utility function to extract NAS PDU from NGAP
        top_key = next(iter(self.segment))
        ies = self.segment[top_key].get("IEs", {})
        nas_pdu_entry = ies.get("id-NAS-PDU")
        if not nas_pdu_entry:
            return None
        return nas_pdu_entry.get("NAS PDU", {})
    
    def print_ngap(self):
        #Utility function for printing NGAP in any of its fields
        try:
            print("[>>] Print NGAP PDU")
            print(json.dumps(self.segment,indent=4))
            """ for pdu_type, pdu_details in ngap.items():
                print(f"\t[>>] PDU Type: {pdu_type}")
                print(f"\t[>>] Procedure Code: {pdu_details['procedure_code']}")
                print(f"\t[>>] Criticality: {pdu_details['criticality']}")
                print(f"\t[>>] Value Length: {pdu_details['value_length']}")
                IEs = pdu_details['IEs']
                for IE_id, IE in IEs.items():
                    print(f"\t[>>] IE ID: {IE_id}")
                    print(f"\t\t[>>] IE Criticality: {IE['IE_criticality']}")
                    print(f"\t\t[>>] IE Length: {IE['IE_length']}")
                    print(f"\t\t[>>] IE Value: {IE['IE_value'].hex()}") """
            return
        except Exception as e:
            print("[!]Error printing ngap:")
            traceback.print_exc()            
            return
        
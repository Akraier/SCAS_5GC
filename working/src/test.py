from pycrate_asn1dir import NGAP
from scapy.all import IP, SCTP, SCTPChunk, SCTPChunkData, Raw


pkt = "02420a64c8c802420a64c810080045020068eea840004084a5c60a64c8100a64c8c8960cd27c6f5567a30000000000030045045c223d000000000000003c20150031000004000100050100414d4600600008000002f839cafe0000564001ff005000100002f839000110080102031008112233000000"
if pkt.haslayer(SCTPChunkData) and pkt[SCTPChunkData].proto_id==60:
    pdu = NGAP_PDU()
    res = pdu.Decode(data=pkt[SCTPChunkData].data)  # gestisce sia BER sia PER a seconda del tipo
if res != 0:
    print("Decoding error:", pdu.GetError())
else:
    print(pdu)


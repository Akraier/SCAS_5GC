from scapy.all import Packet, bind_layers, SCTPChunkData, Raw, StrLenField, BitField, BitEnumField
from scapy.packet import Packet
from scapy.layers.sctp import SCTP_PAYLOAD_PROTOCOL_INDENTIFIERS
from scapy.fields import ByteEnumField, ShortField, StrField, BitField, PacketListField, ConditionalField, PacketField, StrLenField, BitEnumField


procedure_code_values = {
    0: "id-AMFConfigurationUpdate",
    1: "id-AMFStatusIndication",
    2: "id-CellTrafficTrace",
    3: "id-DeactivateTrace",
    4: "id-DownlinkNASTransport",
    5: "id-DownlinkNonUEAssociatedNRPPaTransport",
    6: "id-DownlinkRANConfigurationTransfer",
    7: "id-DownlinkRANStatusTransfer",
    8: "id-DownlinkUEAssociatedNRPPaTransport",
    9: "id-ErrorIndication",
    10: "id-HandoverCancel",
    11: "id-HandoverNotification",
    12: "id-HandoverPreparation",
    13: "id-HandoverResourceAllocation",
    14: "id-InitialContextSetup",
    15: "id-InitialUEMessage",
    16: "id-LocationReportingControl",
    17: "id-LocationReportingFailureIndication",
    18: "id-LocationReport",
    19: "id-NASNonDeliveryIndication",
    20: "id-NGReset",
    21: "id-NGSetup",
    22: "id-OverloadStart",
    23: "id-OverloadStop",
    24: "id-Paging",
    25: "id-PathSwitchRequest",
    26: "id-PDUSessionResourceModify",
    27: "id-PDUSessionResourceModifyIndication",
    28: "id-PDUSessionResourceRelease",
    29: "id-PDUSessionResourceSetup",
    30: "id-PDUSessionResourceNotify",
    31: "id-PrivateMessage",
    32: "id-PWSCancel",
    33: "id-PWSFailureIndication",
    34: "id-PWSRestartIndication",
    35: "id-RANConfigurationUpdate",
    36: "id-RerouteNASRequest",
    37: "id-RRCInactiveTransitionReport",
    38: "id-TraceFailureIndication",
    39: "id-TraceStart",
    40: "id-UEContextModification",
    41: "id-UEContextRelease",
    42: "id-UEContextReleaseRequest",
    43: "id-UERadioCapabilityCheck",
    44: "id-UERadioCapabilityInfoIndication",
    45: "id-UETNLABindingRelease",
    46: "id-UplinkNASTransport",
    47: "id-UplinkNonUEAssociatedNRPPaTransport",
    48: "id-UplinkRANConfigurationTransfer",
    49: "id-UplinkRANStatusTransfer",
    50: "id-UplinkUEAssociatedNRPPaTransport",
    51: "id-WriteReplaceWarning",
    52: "id-SecondaryRATDataUsageReport",
    53: "id-UplinkRIMInformationTransfer",
    54: "id-DownlinkRIMInformationTransfer",
    55: "id-RetrieveUEInformation",
    56: "id-UEInformationTransfer",
    57: "id-RANCPRelocationIndication",
    58: "id-UEContextResume",
    59: "id-UEContextSuspend",
    60: "id-UERadioCapabilityIDMapping",
    61: "id-HandoverSuccess",
    62: "id-UplinkRANEarlyStatusTransfer",
    63: "id-DownlinkRANEarlyStatusTransfer",
    64: "id-AMFCPRelocationIndication",
    65: "id-ConnectionEstablishmentIndication",
    66: "id-BroadcastSessionModification",
    67: "id-BroadcastSessionRelease",
    68: "id-BroadcastSessionSetup",
    69: "id-DistributionSetup",
    70: "id-DistributionRelease",
    71: "id-MulticastSessionActivation",
    72: "id-MulticastSessionDeactivation",
    73: "id-MulticastSessionUpdate",
    74: "id-MulticastGroupPaging",
    75: "id-BroadcastSessionReleaseRequired",
    76: "id-TimingSynchronisationStatus",
    77: "id-TimingSynchronisationStatusReport",
    78: "id-MTCommunicationHandling",
    79: "id-RANPagingRequest",
    80: "id-BroadcastSessionTransport"
}

###Override SCTPChunkData for compatibility#####
""" class MySCTPChunkData(SCTPChunkData):
    def __init__(self, *args, **kwargs):
        super(MySCTPChunkData,self).__init__(*args, **kwargs)
     
def my_guess_payload_class(self, payload):
    print("[!!!!]guess_payload_class called")
    if self.proto_id == 60:
        print("[!!!!!]trying to guess..")
        return NGAPPDU
    return super().guess_payload_class(payload)"""
#SCTPChunkData.guess_payload_class = my_guess_payload_class
#########NGAP-PDU pdu_type definition########
####pdu_type=0 | InitiatinMessage
class InitiatingMessage(Packet):
    name = "InitiatingMessage"
    field_desc = [
        ByteEnumField("procedureCode", 0, procedure_code_values),
        ByteEnumField("criticality", 0, {0: "Reject", 1: "Ignore", 2: "Notify"}),
        StrLenField("value", "", length_from=lambda pkt: len(pkt.payload))  # Placeholder for actual message
    ]
####pdu_type=1 | SuccessfulOutcome
class SuccessfulOutcome(Packet):
    name = "SuccessfulOutcome"
    field_desc = [
        ByteEnumField("procedureCode", 0, procedure_code_values),
        ByteEnumField("criticality", 1, {0: "Reject", 1: "Ignore", 2: "Notify"}),
        StrLenField("value", "", length_from=lambda pkt: len(pkt.payload))  # Placeholder for actual message
    ]
####pdu_type=2 | UnsuccessfulOutcome
class UnsuccessfulOutcome(Packet):
    name = "UnsuccessfulOutcome"
    field_desc = [
        ByteEnumField("procedureCode", 0, procedure_code_values),
        ByteEnumField("criticality", 1, {0: "Reject", 1: "Ignore", 2: "Notify"}),
        StrLenField("value", "", length_from=lambda pkt: len(pkt.payload))  # Placeholder for actual message
    ]
#NGAP-PDU CHOICE Field
class NGAPPDU(Packet):
    name = "NGAP-PDU"
    field_desc = [
        BitEnumField("pdu_type",0,4,{0: "initiatingMessage", 1: "successfulOutcome", 2: "unsuccessfulOutcome"}),
        BitField("reserved",0,4),
        StrLenField("value",Raw(), Raw)
    ]
    """ field_desc = [
        BitField("pdu_type",0,4),   #first 4 bits
        BitField("reserved",0,4),    #next 4 bits || 1B alignment
        StrLenField("value", "", length_from=lambda pkt: len(pkt.payload))
    ] """
    
    #post_dissect is called by scapy to finalize of validate the parsed fields
    
    """ def post_dissection(self, raw_data):
        print("[!] Raw Data (16bytes):",self.raw_data[:16])
        
        print("[!]pdu_type",self.pdu_type)
        if self.pdu_type == 0:
            self.add_payload(InitiatingMessage(self.value))
        if self.pdu_type == 1:
            self.add_payload(SuccessfulOutcome(self.value))
        if self.pdu_type == 2:
            self.add_payload(UnsuccessfulOutcome(self.value)) """

#NAS releted NGAP Procedures
class InitialUEMessage(Packet):
    name = "InitialUEMessage"
    field_desc = [
        #IntField()
    ]

#Binding layers:
#bind_layers(ProtoA, ProtoB, FieldToBind=Value)
#Each time a packet ProtoA()/ProtoB() will be created, the FieldToBind of ProtoA will be equal to Value

try:
    print(SCTPChunkData.__name__)
    print(SCTPChunkData.__module__)
    bind_layers(SCTPChunkData, NGAPPDU, proto_id=60) #Binds SCTP with NGAPPDU every time Payload Protocol Identifier n SCTP is equal to 60
    print(f"NGAPPDU is bound to: {SCTPChunkData.payload_guess}")
    #print(f"Globals \n{globals()}")
    #exit()
except Exception as e:
    print("[!]Binding Failed")
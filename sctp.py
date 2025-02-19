import struct
import socket

sctp_chunk_type = {
    0x00: "SCTPChunkData",
    0x01: "SCTPChunkInit",
    0x02: "SCTPChunkInitAck",
    0x03: "SCTPChunkSack",
    0x04: "SCTPChunkHeartbeatReq",
    0x05: "SCTPChunkHeartbeatAck",
    0x06: "SCTPChunkAbort",
    0x07: "SCTPChunkShutdown",
    0x08: "SCTPChunkShutdownAck",
    0x09: "SCTPChunkError",
    0x0a: "SCTPChunkCookieEcho",
    0x0b: "SCTPChunkCookieAck",
    0x0e: "SCTPChunkShutdownComplete",
    0x0f: "SCTPChunkAuth",
    0x40: "SCTPChunkIData",
    0x82: "SCTPChunkReConfig",
    0x84: "SCTPChunkPayloadData",
    0x80: "SCTPChunkAddressConfAck",
    0xc0: "SCTPChunkForwardTSN",
    0xc1: "SCTPChunkAsConf",
    0xc2: "SCTPChunkIForwardTSN",
}

class SCTP_chunk:
    def __init__(self,SCTP_payload):
        #chunk header
        self.chunk_type, self.chunk_flags, self.chunk_length = struct.unpack('!BBH', SCTP_payload[:4])
        self.chunk_value = SCTP_payload[4:self.chunk_length]
    
    def print_SCTP_chunk(self):
        print("[>>]SCTP Chunk\n\
                [>>]Chunk Type: {}\n\
                [>>]Chunk Flags: {}\n\
                [>>]Chunk Length: {}\n\
                [>>]Chunk Value: {}".format(self.chunk_type, self.chunk_flags, self.chunk_length, self.chunk_value.hex()))
    
    def identify_chunk(self):
        return sctp_chunk_type[self.chunk_type]
    

class SCTP_Data_chunk:
    def __init__(self,SCTP_chunk):
        self.flags, self.length, self.stream_id, self.stream_seq, self.payload = struct.unpack('!BBHLL', SCTP_chunk[:12])

    def print_SCTP_chunk_data(self):
        print("[>>]SCTP Chunk Data\n\
                [>>]Flags: {}\n\
                [>>]Length: {}\n\
                [>>]Stream ID: {}\n\
                [>>]Stream Seq: {}\n\
                [>>]Payload: {}".format(self.flags, self.length, self.stream_id, self.stream_seq, self.payload))

class SCTP:
    def __init__(self, packet):
        try:
            #Retrieve source and dest IP addresses
            self.src_ip = socket.inet_ntoa(packet[26:30])
            self.dest_ip = socket.inet_ntoa(packet[30:34])
            # Discard Ethernet and IP headers [34B=14B ETH +20B IP]
            SCTP_segment = packet[34:]
            # Dissect SCTP header [12B]
            self.src_port, self.dest_port, self.verification_tag, self.checksum = struct.unpack('!HHLL', SCTP_segment[:12])
            # Dissect SCTP chunks
            self.chunks = []
            payload = SCTP_segment[12:]
            while len(payload) >= 4:
                chunk = SCTP_chunk(payload)
                self.chunks.append(chunk)
                payload = payload[chunk.chunk_length:]
        except Exception as e:
            print("[!]Error dissecting SCTP packet:", e, "\nPacket data:", packet.hex())

    def print_SCTP(self):
        print("[>>]SCTP packet\n\
                [>>]Src IP: {}\n\
                [>>]Dest IP: {}\n\
                [>>]Src Port: {}\n\
                [>>]Dest Port: {}\n\
                [>>]Verification Tag: {}\n\
                [>>]Checksum: {}\n".format(self.src_ip,self.dest_ip,self.src_port, self.dest_port, self.verification_tag, self.checksum))
        """ for chunk in self.chunks:
            chunk.print_SCTP_chunk()"""
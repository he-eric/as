import binascii
import socket as syssock
import struct
import sys
import random
import threading

# these functions are global to the class and
# define the UDP ports all messages are sent
# and received from
import time

receivePort = None
sendPort = None
receiveSocket = None
sendSocket = None

HEADER_FORMAT = "!BBBBHHLLQQLL"
VERSION = 1
# flags = 0
OPT_PTR = 0
PROTOCOL = 0
HEADER_LEN = 40
CHECK_SUM = 0
SOURCE_PORT = 0
DEST_PORT = 0
sequence_no = 0
ack_no = 0
WINDOW = 0

MAX_BYTES_TO_RECEIVE = 64000
SENDER_WINDOW = 50

initial_seq_no = 0

expected_num_of_acks = 0

received_file_len = False
sent_file_len = False

file_len = 0

list_of_unacked_packets = []
packet_timed_out = False
sending_done = False
sent_bytes = 0

attribute_to_index_of_unpacked_struct_map = {
    "version": 0,
    "flags": 1,
    "opt_ptr": 2,
    "protocol": 3,
    "header_len": 4,
    "checksum": 5,
    "source_port": 6,
    "dest_port": 7,
    "sequence_no": 8,
    "ack_no": 9,
    "window": 10,
    "payload_len": 11,
    "payload": 12
}


def get_attribute_from_unpacked_struct(attribute, unpacked_struct):
    return unpacked_struct[attribute_to_index_of_unpacked_struct_map[attribute]]


def init(UDPportTx, UDPportRx):  # initialize your UDP socket here
    global receivePort
    global sendPort
    global receiveSocket
    global sendSocket
    sendPort = int(UDPportTx)
    if sendPort == 0:
        sendPort = 1453
    receivePort = int(UDPportRx)
    if receivePort == 0:
        receivePort = 1066
    receiveSocket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    sendSocket = syssock.socket(syssock.AF_INET, syssock.SOCK_DGRAM)
    receiveSocket.bind(
        (syssock.gethostname(), receivePort))  # server will try to receive a message from the receive port


def extractAddressFromPayload(myAddress):
    address = myAddress.split("@")
    return (address[0], int(address[1]))


class socket:

    def __init__(self):  # fill in your code here
        self.clientSocketOfServer = None  # I have these here for easy reference (so we can keep track of the fields)
        self.destinationAddress = None  # However, I don't think having them in __init__() is actually needed
        self.isClient = True
        return

    def bind(self, address):
        return

        # address is a tuple: (destinationIP, port)

    def connect(self, address):  # fill in your code here

        self.isClient = True
        # only client calls this
        # address is (serverAddressToConnectTo, port)
        # send client address to server
        # then server sends ack (accept())
        # then client sends ack as well (3 way handshake)
        ###################################
        global ack_no
        global sequence_no
        global initial_seq_no

        myAddress = syssock.gethostname() + "@" + str(receivePort) + '@'

        payload_len = 50
        flags = 1  # SYN
        sequence_no = random.randint(1, 200)
        initial_seq_no = sequence_no

        message = struct.pack(HEADER_FORMAT + "50s", VERSION, flags, OPT_PTR, PROTOCOL, HEADER_LEN, CHECK_SUM,
                              SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, payload_len, myAddress)

        sendSocket.sendto(message, (address[0], sendPort))
        # server must now accept(); i.e., it must send a message to the client as per the 3-way handshake
        # this means the client must receive this message:
        while True:

            serversInitialAckMsg, addrOfServersSendSocket = receiveSocket.recvfrom(1024)
            unpackedStruct = struct.unpack(HEADER_FORMAT + "50s", serversInitialAckMsg)

            flagsOfMessage = get_attribute_from_unpacked_struct("flags", unpackedStruct)
            if not flagsOfMessage == 5:
                return

            self.destinationAddress = extractAddressFromPayload(
                get_attribute_from_unpacked_struct("payload", unpackedStruct))

            if self.destinationAddress is None:  # if fail to extract address from message, assume it's the
                self.destinationAddress = address  # same address we sent our initial connection request to

            # from the server's initial ack message, but leaving this here just in case
            # i think we actually are supposed to decide if the msg contains this info for ourselves

            # send an ack back as the final part of the 3 way handshake
            flags = 4  # ACK
            ack_no = get_attribute_from_unpacked_struct("sequence_no", unpackedStruct) + 1  # prev msg's seqNo + 1
            sequence_no += 1
            payload_len = 0

            message = struct.pack(HEADER_FORMAT, VERSION, flags, OPT_PTR, PROTOCOL, HEADER_LEN, CHECK_SUM,
                                  SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, payload_len)

            sendSocket.sendto(message, (address[0], sendPort))
            sequence_no += 1
            break

        return

    def listen(self, backlog):
        return

    def accept(self):

        self.isClient = False

        global sequence_no
        global ack_no

        while True:

            clientConnRequestMsg, addrOfClientsSendSocket = receiveSocket.recvfrom(1024)

            unpackedStruct = struct.unpack(HEADER_FORMAT + "50s", clientConnRequestMsg)

            flagsOfMessage = get_attribute_from_unpacked_struct("flags", unpackedStruct)
            if not flagsOfMessage == 1:  # NOT a connection request
                return

            self.clientSocketOfServer = syssock.socket(syssock.AF_INET,
                                                       syssock.SOCK_DGRAM)

            self.destinationAddress = extractAddressFromPayload(
                get_attribute_from_unpacked_struct("payload", unpackedStruct))

            if self.destinationAddress is None:
                self.destinationAddress = addrOfClientsSendSocket

            myAddress = syssock.gethostname() + '@' + str(receivePort) + '@'
            payLoad = get_attribute_from_unpacked_struct("payload", unpackedStruct)
            sendAddress = extractAddressFromPayload(payLoad)

            flags = 5  # SYN and ACK

            ack_no = get_attribute_from_unpacked_struct("sequence_no", unpackedStruct) + 1  # seqNo + 1
            payload_len = 50

            structServerPacket = struct.pack(HEADER_FORMAT + "50s", VERSION, flags, OPT_PTR, PROTOCOL, HEADER_LEN,
                                             CHECK_SUM,
                                             SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, payload_len,
                                             myAddress)

            sendSocket.sendto(structServerPacket, sendAddress)

            clientConnRequestMsg, addrOfClientsSendSocket = receiveSocket.recvfrom(1024)
            unpackedStruct = struct.unpack(HEADER_FORMAT, clientConnRequestMsg)

            ack_no = get_attribute_from_unpacked_struct("sequence_no", unpackedStruct) + 1
            break

        return self, self.destinationAddress  # not sure which address to return

    def close(self):  # fill in your code here
        # client calls close
        # client should send something to server
        # then client should receive something from the server
        global HEADER_LEN
        global HEADER_FORMAT
        global sequence_no
        global ack_no

        if self.isClient:

            payload_len = 0
            flags = 2
            packed_struct = struct.pack(HEADER_FORMAT, VERSION, flags, OPT_PTR, PROTOCOL, HEADER_LEN,
                                        CHECK_SUM, SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, payload_len)

            receiveSocket.settimeout(3)
            while True:
                sendSocket.sendto(packed_struct, self.destinationAddress)
                try:
                    received_struct1, addr = receiveSocket.recvfrom(HEADER_LEN)
                    received_struct2, addr = receiveSocket.recvfrom(HEADER_LEN)
                except:
                    continue

                unpacked_struct = struct.unpack(HEADER_FORMAT, received_struct1)
                received_ack_no = get_attribute_from_unpacked_struct("ack_no", unpacked_struct)
                received_flags = get_attribute_from_unpacked_struct("flags", unpacked_struct)
                if not (received_ack_no == sequence_no + 1 and received_flags == 4):
                    continue

                unpacked_struct = struct.unpack(HEADER_FORMAT, received_struct2)
                received_seq_no = get_attribute_from_unpacked_struct("sequence_no", unpacked_struct)
                received_flags = get_attribute_from_unpacked_struct("flags", unpacked_struct)
                if received_flags == 2:
                    break

            sequence_no += 1
            ack_no = received_seq_no + 1
            flags = 4
            packed_struct = struct.pack(HEADER_FORMAT, VERSION, flags, OPT_PTR, PROTOCOL, HEADER_LEN,
                                        CHECK_SUM, SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, payload_len)
            sendSocket.sendto(packed_struct, self.destinationAddress)

        else:
            while True:
                try:
                    received_struct, addr = receiveSocket.recvfrom(HEADER_LEN)
                except:
                    continue
                try:
                    unpacked_struct = struct.unpack(HEADER_FORMAT, received_struct)
                except Exception as e:
                    continue

                received_seq_no = get_attribute_from_unpacked_struct("sequence_no", unpacked_struct)
                received_flags = get_attribute_from_unpacked_struct("flags", unpacked_struct)
                if received_flags == 2:
                    break

            ack_no = received_seq_no + 1
            while True:

                packed_struct1 = struct.pack(HEADER_FORMAT, VERSION, 4, OPT_PTR, PROTOCOL, HEADER_LEN,
                                            CHECK_SUM, SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, 0)

                packed_struct2 = struct.pack(HEADER_FORMAT, VERSION, 2, OPT_PTR, PROTOCOL, HEADER_LEN,
                                            CHECK_SUM, SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, 0)

                sendSocket.sendto(packed_struct1, self.destinationAddress)
                time.sleep(0.01)
                sendSocket.sendto(packed_struct2, self.destinationAddress)
                try:
                    received_struct, addr = receiveSocket.recvfrom(HEADER_LEN)
                    unpacked_struct = struct.unpack(HEADER_FORMAT, received_struct)
                    received_flags = get_attribute_from_unpacked_struct("flags", unpacked_struct)
                    if received_flags == 4:
                        return
                except:
                    continue

        return

    def packet_timed_out_triggered(self, seq):
        global packet_timed_out
        print "packet " + str(seq)+ " timed out"
        packet_timed_out = True

    def send_thread(self, buffer):
        # only client will call this
        # call sendTo(msg, self.destinationAddress)
        # fill in your code here
        global sent_file_len
        global packet_timed_out
        global sequence_no
        global sending_done
        global list_of_unacked_packets
        global file_len
        global sent_bytes
        global MAX_BYTES_TO_RECEIVE
        file_len = len(buffer)

        last_sequence_no = sequence_no - 1

        # Counter for while loop, will be incremented
        num_bytes_sent = 0

        # Counter for while loop
        total_bytes_to_send = len(buffer)
        last_pay_load_len = total_bytes_to_send % (MAX_BYTES_TO_RECEIVE - HEADER_LEN)

        # Flags to be set
        flags = 0

        # CASE 1: File is less than payload length send once
        if total_bytes_to_send <= MAX_BYTES_TO_RECEIVE - HEADER_LEN:
            packed_struct = struct.pack(HEADER_FORMAT + str(len(buffer)) + "s", VERSION, flags, OPT_PTR, PROTOCOL,
                                        HEADER_LEN, CHECK_SUM,
                                        SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, total_bytes_to_send,
                                        buffer)
            sendSocket.sendto(packed_struct, self.destinationAddress)

            list_of_unacked_packets.append((sequence_no, threading.Timer(0.2, self.packet_timed_out_triggered, [str(sequence_no)])))
            list_of_unacked_packets[len(list_of_unacked_packets)-1][1].start()
            sequence_no+=1

            # Only sending one packet; If ack is never received by sender process
            # Length will always be > 1 and will stay within loop until ack is timed out
            while len(list_of_unacked_packets) > 0:
                if packet_timed_out:
                    packet_timed_out = False
                    sendSocket.sendto(packed_struct, self.destinationAddress)

            sending_done = True
            sent_bytes = total_bytes_to_send
            return total_bytes_to_send

        # CASE 2: file len > maximum payload we can send
        payload_len = MAX_BYTES_TO_RECEIVE - HEADER_LEN
        # Begin and end are the range of the file to be sent
        # EG: send file from range [0:100] [101:200] [201:300]
        begin = 0
        end = payload_len
        # Set a endless loop
        while True:
            # if num bytes sent < total

            # else if list not empty

            if packet_timed_out:
                tupleDroppedSeqNo = list_of_unacked_packets[0]
                for tuple in list_of_unacked_packets:
                    tuple[1].cancel()

                packet_timed_out = False

                num_bytes_sent = ((tupleDroppedSeqNo[0] - (initial_seq_no+2)) * payload_len)
                begin = num_bytes_sent
                end = begin + payload_len
                sequence_no = tupleDroppedSeqNo[0]

                # Reset the list to no packets
                list_of_unacked_packets = []
                continue
            if len(list_of_unacked_packets) >= SENDER_WINDOW:
                continue

            if (sequence_no - (initial_seq_no+2)) * payload_len < total_bytes_to_send - last_pay_load_len:
                time.sleep(0.07)
                # Pack into struct
                packed_struct = struct.pack(HEADER_FORMAT + str(payload_len) + "s", VERSION, flags, OPT_PTR,
                                            PROTOCOL, HEADER_LEN, CHECK_SUM,
                                            SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW,
                                            payload_len, buffer[begin:end])

                # Send packed struct to destination
                sendSocket.sendto(packed_struct, self.destinationAddress)

                # Set a timer on the expected ack and put in list
                list_of_unacked_packets.append((sequence_no, threading.Timer(.2, self.packet_timed_out_triggered, [str(sequence_no)])))
                list_of_unacked_packets[len(list_of_unacked_packets)-1][1].start()

                # Increment sequence number
                sequence_no += 1

                # Change range of buffer
                begin += payload_len
                end += payload_len

                # Increment counter
                num_bytes_sent += payload_len

            elif len(list_of_unacked_packets) > 0:
                continue

            else:
                break

        # Get size of last packet to send
        if total_bytes_to_send == num_bytes_sent:
            sending_done = True
            sent_bytes = num_bytes_sent
            return num_bytes_sent

        # Pack
        payload_len = file_len % (MAX_BYTES_TO_RECEIVE - HEADER_LEN)

        packed_struct = struct.pack(HEADER_FORMAT + str(payload_len) + "s", VERSION, flags, OPT_PTR,
                                    PROTOCOL, HEADER_LEN, CHECK_SUM,
                                    SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW,
                                    payload_len, buffer[begin:end])

        # Send LAST packet
        sendSocket.sendto(packed_struct, self.destinationAddress)
        list_of_unacked_packets.append((sequence_no, threading.Timer(0.2, self.packet_timed_out_triggered, [str(sequence_no)])))
        list_of_unacked_packets[len(list_of_unacked_packets)-1][1].start()

        while len(list_of_unacked_packets) > 0:
            time.sleep(0.1)
            if packet_timed_out:
                packed_struct = struct.pack(HEADER_FORMAT + str(payload_len) + "s", VERSION, flags, OPT_PTR,
                                            PROTOCOL, HEADER_LEN, CHECK_SUM,
                                            SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW,
                                            payload_len, buffer[begin:end])
                packet_timed_out = False
                sendSocket.sendto(packed_struct, self.destinationAddress)
                list_of_unacked_packets = []
                list_of_unacked_packets.append((sequence_no, threading.Timer(0.2, self.packet_timed_out_triggered, [str(sequence_no)])))
                list_of_unacked_packets[0][1].start()
        sequence_no += 1
        sending_done = True

        num_bytes_sent += payload_len

        # Return total amount sent
        sent_bytes = num_bytes_sent
        return num_bytes_sent

    def receive_thread(self):
        global list_of_unacked_packets
        global sending_done
        global sequence_no
        receiveSocket.settimeout(1)

        while True:

            if sending_done:
                break

            if packet_timed_out:
                continue

            try:
                packet, add = receiveSocket.recvfrom(HEADER_LEN)
                if packet_timed_out:
                    continue

            except:
                continue

            unpacked_struct = struct.unpack(HEADER_FORMAT, packet)

            received_ack_no = get_attribute_from_unpacked_struct("ack_no", unpacked_struct)

            # Receive ack number
            # Compare received ack number to first seq number in list
            # Go to list of timer objects and delete before timer goes off
            for i in range(len(list_of_unacked_packets)):
                list_of_unacked_packets[i][1].cancel()
                if list_of_unacked_packets[i][0] == received_ack_no - 1:
                    list_of_unacked_packets = list_of_unacked_packets[i+1:]
                    break

    def send(self, buffer):
        global sent_file_len
        global expected_num_of_acks
        global file_len
        global sent_bytes
        file_len = len(buffer)

        global MAX_BYTES_TO_RECEIVE

        if not sent_file_len:
            unpacked_buffer = struct.unpack("!L", buffer)
            sendSocket.sendto(str(unpacked_buffer[0]), self.destinationAddress)
            sent_file_len = True
            return


        cs1 = threading.Thread(name='send', target=self.send_thread, args=(buffer,))
        cs2 = threading.Thread(name='receive', target=self.receive_thread)
        cs1.start()
        cs2.start()

        cs1.join()
        cs2.join()

        return sent_bytes

    def recv(self, nbytes):
        global received_file_len
        global file_len
        global ack_no
        buffer = ""

        global MAX_BYTES_TO_RECEIVE   # 65,356 bytes is 64K bytes

        if not received_file_len:
            initial_message, add = receiveSocket.recvfrom(MAX_BYTES_TO_RECEIVE)

            received_file_len = True
            packed_message = struct.pack("!L", int(initial_message))
            file_len = int(initial_message)

            return packed_message  # server1.py actually wants the packed struct, not the unpacked struct.
        max_size_packet_format = HEADER_FORMAT + str(MAX_BYTES_TO_RECEIVE - HEADER_LEN) + "s"

        size_of_last_payload = file_len % (MAX_BYTES_TO_RECEIVE - HEADER_LEN)

        last_packet_format = HEADER_FORMAT + str(size_of_last_payload) + "s"

        num_bytes_received = 0
        while num_bytes_received + MAX_BYTES_TO_RECEIVE - HEADER_LEN <= file_len - size_of_last_payload:

            msg_received, add = receiveSocket.recvfrom(MAX_BYTES_TO_RECEIVE)
            try:
                unpacked_struct = struct.unpack(max_size_packet_format, msg_received)
            except Exception as e:
                continue
            payload_received_len = get_attribute_from_unpacked_struct("payload_len", unpacked_struct)
            payload = get_attribute_from_unpacked_struct("payload", unpacked_struct)
            received_seq_no = get_attribute_from_unpacked_struct("sequence_no", unpacked_struct)
            if received_seq_no != ack_no:
                continue

            num_bytes_received += payload_received_len
            ack_no += 1
            buffer += payload

            payload_len = 0  # no payload
            flags = 4  # ACK
            packed_ack = struct.pack(HEADER_FORMAT, VERSION, flags, OPT_PTR, PROTOCOL,
                                     HEADER_LEN, CHECK_SUM,
                                     SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, payload_len)
            sendSocket.sendto(packed_ack, self.destinationAddress)

        # last payload:
        if (num_bytes_received == file_len):
            return buffer

        msg_received, add = receiveSocket.recvfrom(MAX_BYTES_TO_RECEIVE)
        unpacked_struct = struct.unpack(last_packet_format, msg_received)
        payload_received_len = get_attribute_from_unpacked_struct("payload_len", unpacked_struct)
        num_bytes_received += payload_received_len

        pl = get_attribute_from_unpacked_struct("payload", unpacked_struct)
        buffer += pl

        payload_len = 0  # no payload
        flags = 4  # ACK
        ack_no += 1
        packed_ack = struct.pack(HEADER_FORMAT, VERSION, flags, OPT_PTR, PROTOCOL,
                                 HEADER_LEN, CHECK_SUM,
                                 SOURCE_PORT, DEST_PORT, sequence_no, ack_no, WINDOW, payload_len)
        sendSocket.sendto(packed_ack, self.destinationAddress)
        received_file_len = False
        return buffer

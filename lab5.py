# -*- coding: utf-8 -*-
"""
CPSC 5520, Seattle University
This is free and unencumbered software released into the public domain.
:Authors: Aditya Ganti
:Assignment: Lab 5
:EC Displaying transactions within SU ID block: Attempted
"""
import hashlib
import ipaddress
import socket
import struct
import sys
import time

from typing import Union

MAINNET = 'f9beb4d9'
VERSION = 70015
LISTENER_ADDRESS = '143.110.240.88', 8333
HDR_SZ = 24
SU_ID_MODULO = 1225
GENESIS_BLOCK_HASH = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'


class Lab5:
    def __init__(self):
        """
        Constructor for the Lab5 class
        """
        self.block_messages_count = 0
        self.reqd_block_header = []
        self.su_id_block_transactions = []

        payload = self.init_version_payload()
        header = self.init_header('version', payload)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(LISTENER_ADDRESS)

        self.print_message(header + payload, 'sending')
        self.send_message(header, payload)

        data = self.sock.recv(2**16)
        self.print_message(data, 'received')

        # data = self.sock.recv(2**16)
        # self.print_message(data, 'received')

        self.print_message(self.init_header('verack') + b'', 'sending')
        self.send_message(self.init_header('verack'), b'')

        data = self.sock.recv(2**16)
        self.print_message(data, 'received')

        self.find_su_id_block()

        payload = self.init_getdata_payload("MSG_TX", self.reqd_block_header[1])
        header = self.init_header('getdata', payload)
        self.print_message(header + payload, 'sending')
        self.send_message(header, payload)
        while True:
            data = self.sock.recv(2 ** 16)
            if not data:
                break
            self.print_message(data, 'received', 'getdata')
            print("waiting for another getdata response message")
        print("\nFinished receiving all messages in the SU ID block\n")

        self.print_transactions()

    def find_su_id_block(self) -> None:
        """
        This function is responsible for finding the SU ID block
        :return: None
        """
        payload = self.init_genesisblocks_payload()
        header = self.init_header('getblocks', payload)
        self.print_message(header + payload, 'sending')
        self.send_message(header, payload)

        while not self.reqd_block_header:
            data = self.sock.recv(2 ** 16)
            latest_hash_header = self.print_message(data, 'received', 'getblocks')
            if latest_hash_header:
                print(f"Latest hash header is : ", latest_hash_header)
            if not latest_hash_header:
                continue
            if self.reqd_block_header:
                break
            payload = self.init_getblocks_payload(latest_hash_header)
            header = self.init_header('getblocks', payload)
            self.send_message(header, payload)
            print("Sending another getblocks request to get the remaining blocks")

        print(f"Required block header hash is : ", self.reqd_block_header)

    def send_message(self, header: bytes, payload: bytes) -> None:
        """
        This function is responsible for sending the message to the socket
        :param header: header of the message
        :param payload: payload of the message
        :return: None
        """
        self.sock.sendall(header + payload)

    def init_header(self, command: str, payload: bytes = b'') -> bytes:
        """
        This function is responsible for initializing the header of the message
        :param command: command of the message
        :param payload: payload of the message
        :return: header of the message
        """
        start_string = MAINNET
        command_name = command.encode()
        padded_command_name = command_name + b"\x00" * (12 - len(command_name))
        payload_size = self.uint32_t(len(payload))
        chksum = self.checksum(payload)[:4]

        return bytes.fromhex(start_string + padded_command_name.hex() + payload_size.hex() + chksum.hex())

    @staticmethod
    def checksum(payload: bytes) -> bytes:
        """
        This function is responsible for calculating the checksum of the payload
        :param payload: payload of the message
        :return: checksum of the payload
        """
        return hashlib.sha256(hashlib.sha256(payload).digest()).digest()

    def init_ping_payload(self) -> bytes:
        """
        This function is responsible for initializing the ping payload
        :return: ping payload
        """
        return self.uint64_t(18964)

    def init_version_payload(self) -> bytes:
        """
        This function is responsible for initializing the payload for the version message
        :return: version payload
        """
        # print("VERSION\n-----------------------------------")
        version = self.int32_t(VERSION)
        # print(f"Version: {version.hex()}")
        services = self.uint64_t(0)
        # print(f"Services: {services.hex()}")
        timestamp = self.int64_t(int(time.time()))
        # print(f"Timestamp: {timestamp.hex()}")

        addr_recv_services = self.uint64_t(1)
        # print(f"Addr_recv_services: {addr_recv_services.hex()}")
        addr_recv_ip = self.ipv6_from_ipv4(LISTENER_ADDRESS[0])
        # print(f"Addr_recv_ip: {addr_recv_ip.hex()}")
        addr_recv_port = self.uint16_t(8333)
        # print(f"Addr_recv_port: {addr_recv_port.hex()}")

        addr_trans_services = self.uint64_t(0)
        # print(f"Addr_trans_services: {addr_trans_services.hex()}")
        addr_trans_ip = self.ipv6_from_ipv4("127.0.0.1")
        # print(f"Addr_trans_ip: {addr_trans_ip.hex()}")
        addr_trans_port = self.uint16_t(8333)
        # print(f"Addr_trans_port: {addr_trans_port.hex()}")

        nonce = self.uint64_t(0)
        # print(f"Nonce: {nonce.hex()}")
        user_agent_bytes = self.compactsize_t(0)
        # print(f"User_agent_bytes: {user_agent_bytes.hex()}")
        start_height = self.int32_t(0)
        # print(f"Start_height: {start_height.hex()}")
        relay = self.bool_t(False)
        # print(f"Relay: {relay.hex()}")

        final_payload = version + services + timestamp + addr_recv_services + \
            addr_recv_ip + addr_recv_port + addr_trans_services + \
            addr_trans_ip + addr_trans_port + nonce + user_agent_bytes + \
            start_height + relay

        return final_payload

    def init_getdata_payload(self, inv_msg_type: str, inv_hash: str) -> bytes:
        """
        This function is responsible for initializing the payload for the getdata message
        :param inv_msg_type: type of the message
        :param inv_hash: hash of the message
        :return: getdata payload
        """
        count = self.compactsize_t(1)
        inv_type = bytes(inv_msg_type, encoding='utf-8')
        inv_hash = bytes.fromhex(inv_hash)

        return count + inv_type + inv_hash

    def init_sendcmpct_payload(self) -> bytes:
        """
        This function is responsible for initializing the payload for the sendcmpct message
        :return: sendcmpct payload
        """
        announce = self.bool_t(True)
        version = self.uint64_t(1)
        return announce + version

    def init_genesisblocks_payload(self) -> bytes:
        """
        This function is responsible for initializing the payload for the genesisblocks message
        :return: genesisblocks payload
        """
        version = self.uint32_t(VERSION)
        hash_count = self.compactsize_t(1)
        hashes = bytes.fromhex(GENESIS_BLOCK_HASH)
        stop_hash = self.checksum(int(0).to_bytes(32, byteorder=sys.byteorder))

        return version + hash_count + hashes + stop_hash

    def init_getblocks_payload(self, start_hash: str, stop_hash: int = 0) -> bytes:
        """
        This function is responsible for initializing the payload for the getblocks message
        :param start_hash: start hash of the message
        :param stop_hash: stop hash of the message
        :return: getblocks payload
        """
        version = self.uint32_t(VERSION)
        hash_count = self.compactsize_t(1)
        hashes = bytes.fromhex(start_hash)
        stop_hash = self.checksum(int(stop_hash).to_bytes(32, byteorder=sys.byteorder))

        return version + hash_count + hashes + stop_hash

    def init_getblocktxn_payload(self, block_hash: str) -> bytes:
        """
        This function is responsible for initializing the payload for the getblocktxn message
        :param block_hash: hash of the block
        :return: getblocktxn payload
        """
        indexes_count = self.compactsize_t(1)
        indexes = self.compactsize_t(0)

        return bytes.fromhex(block_hash) + indexes_count + indexes

    def compactsize_t(self, n: int) -> bytes:
        """
        This function is responsible for converting the integer to compactsize_t
        :param n: integer to be converted
        :return: compactsize_t
        """
        if n < 252:
            return self.uint8_t(n)
        if n < 0xffff:
            return self.uint8_t(0xfd) + self.uint16_t(n)
        if n < 0xffffffff:
            return self.uint8_t(0xfe) + self.uint32_t(n)
        return self.uint8_t(0xff) + self.uint64_t(n)

    @staticmethod
    def unmarshal_int(b: bytes) -> int:
        """
        Unmarshal a little-endian integer from the given bytes
        :param b: bytes to unmarshal
        :return: integer
        """
        return int.from_bytes(b, byteorder='little', signed=True)

    @staticmethod
    def unmarshal_uint(b: bytes, byteorder=sys.byteorder) -> int:
        """
        Unmarshal a little-endian unsigned integer from the given bytes
        :param b: bytes to unmarshal
        :param byteorder: byte order
        :return: unsigned integer
        """
        return int.from_bytes(b, byteorder=byteorder, signed=False)

    def print_message(self, msg: bytes, text: Union[str, None] = None, flag: Union[str, None] = None) -> Union[str, None]:
        """
        Report the contents of the given bitcoin message
        :param msg: bitcoin message (bytes or bytearray)
        :param text: text to print before the message
        :param flag: getblocks or getdata
        :return: last hash in the inv message
        """
        print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
        print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
        header = msg[:HDR_SZ]
        payload_size = self.unmarshal_uint(header[16:20])
        payload = msg[HDR_SZ:HDR_SZ + payload_size]
        command = self.print_header(msg[:HDR_SZ], self.checksum(payload)[:4])
        if command == 'version':
            self.print_version_msg(payload)
        if command == 'inv':
            return self.print_inv_msg(payload, flag)
        # FIXME print out the payloads of other types of messages, too
        return None

    def print_inv_msg(self, b: bytes, flag: str = None) -> Union[str, None]:
        """
        Report the contents of the given bitcoin inv message (sans the header)
        :param b: inv message contents
        :param flag: getblocks or getdata
        :return: last hash in the inv message
        """
        count_bytes, countsize = self.unmarshal_compactsize(b)
        data = b[len(count_bytes):]
        invs = []
        for i in range(0, countsize*40, 36):
            inv_type = data[i:i + 4]
            inv_hash = data[i + 4:i + 36]
            if not inv_type or not inv_hash:
                break
            invs.append((inv_type.hex(), inv_hash.hex()))
            if self.block_messages_count == SU_ID_MODULO:
                self.reqd_block_header = inv_type.hex(), inv_hash.hex()
            else:
                self.block_messages_count += 1

        # print report
        prefix = '  '
        print(prefix + 'INV')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} count'.format(prefix, countsize))

        # return invs[-1][1]
        if flag == 'getblocks':
            return invs[-1][1]
        if flag == 'getdata':
            for x in invs:
                self.su_id_block_transactions.append(x)

        for inv in invs:
            # printing the type on one line, and the corresponding hash on the next
            print('{}{:32} type'.format(prefix, inv[0]))
            print('{}{:16} '.format(prefix, inv[1][:32]))
            print('{}{:16} Hash (TXID)'.format(prefix, inv[1][32:]))
            print()
            break

    def print_transactions(self) -> None:
        """
        This function is responsible for printing all the transactions in the SU ID block
        :return: None
        """
        print("Printing all the transactions in the SU ID block")
        # print report
        prefix = '  '
        print(prefix + 'INV')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} count'.format(prefix, len(self.su_id_block_transactions)))

        for inv in self.su_id_block_transactions:
            # printing the type on one line, and the corresponding hash on the next
            print('{}{:32} type'.format(prefix, inv[0]))
            print('{}{:16} '.format(prefix, inv[1][:32]))
            print('{}{:16} Hash (TXID)'.format(prefix, inv[1][32:]))
            print()

    def print_version_msg(self, b: bytes) -> None:
        """
        Report the contents of the given bitcoin version message (sans the header)
        :param b: version message contents
        :return: None
        """
        # pull out fields
        version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
        rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
        nonce = b[72:80]
        user_agent_size, uasz = self.unmarshal_compactsize(b[80:])
        i = 80 + len(user_agent_size)
        user_agent = b[i:i + uasz]
        i += uasz
        start_height, relay = b[i:i + 4], b[i + 4:i + 5]
        extra = b[i + 5:]

        # print report
        prefix = '  '
        print(prefix + 'VERSION')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} version {}'.format(prefix, version.hex(), self.unmarshal_int(version)))
        print('{}{:32} my services'.format(prefix, my_services.hex()))
        time_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(self.unmarshal_int(epoch_time)))
        print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
        print('{}{:32} your services'.format(prefix, your_services.hex()))
        print('{}{:32} your host {}'.format(prefix, rec_host.hex(), self.ipv6_to_ipv4(rec_host)))
        print('{}{:32} your port {}'.format(prefix, rec_port.hex(), self.unmarshal_uint(rec_port, 'big')))
        print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
        print('{}{:32} my host {}'.format(prefix, my_host.hex(), self.ipv6_to_ipv4(my_host)))
        print('{}{:32} my port {}'.format(prefix, my_port.hex(), self.unmarshal_uint(my_port, 'big')))
        print('{}{:32} nonce'.format(prefix, nonce.hex()))
        print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
        print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
        print('{}{:32} start height {}'.format(prefix, start_height.hex(), self.unmarshal_uint(start_height)))
        print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
        if len(extra) > 0:
            print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))

    def print_header(self, header: bytes, expected_cksum: Union[bytes, None] = None) -> str:
        """
        Report the contents of the given bitcoin message header
        :param header: bitcoin message header
        :param expected_cksum: expected checksum
        :return: command of the message
        """
        magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
        command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
        command = bytearray([b for b in command_hex if b != 0]).decode('utf-8', errors='replace')
        psz = self.unmarshal_uint(payload_size)
        if expected_cksum is None:
            verified = ''
        elif expected_cksum == cksum:
            verified = '(verified)'
        else:
            verified = '(WRONG!! ' + expected_cksum.hex() + ')'
        prefix = '  '
        print(prefix + 'HEADER')
        print(prefix + '-' * 56)
        prefix *= 2
        print('{}{:32} magic'.format(prefix, magic.hex()))
        print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
        print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
        print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
        return command

    @staticmethod
    def int_to_uint32_t(value):
        # Ensure that the value is within the valid range for an uint32_t
        if not (0 <= value <= 0xFFFFFFFF):
            raise ValueError("Value is not within the valid range for uint32_t")

        # Define the format string for struct.pack
        fmt = "<I"  # I represents a 4-byte unsigned integer (uint32_t) in little-endian byte order

        # Pack the value into a binary string
        uint32_t_bytes = struct.pack(fmt, value)

        return uint32_t_bytes

    @staticmethod
    def int_to_int32_t(value):
        # Ensure that the value is within the valid range for an int32_t
        if not (-0x80000000 <= value <= 0x7FFFFFFF):
            raise ValueError("Value is not within the valid range for int32_t")

        # Define the format string for struct.pack
        fmt = "<i"  # i represents a 4-byte signed integer (int32_t) in little-endian byte order

        # Pack the value into a binary string
        int32_t_bytes = struct.pack(fmt, value)

        return int32_t_bytes

    @staticmethod
    def int_to_uint64_t(value):
        # Ensure that the value is within the valid range for a uint64_t
        if not (0 <= value <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("Value is not within the valid range for uint64_t")

        # Define the format string for struct.pack
        fmt = "<Q"  # Q represents an 8-byte unsigned integer (uint64_t) in little-endian byte order

        # Pack the value into a binary string
        uint64_t_bytes = struct.pack(fmt, value)

        return uint64_t_bytes

    @staticmethod
    def int_to_int64_t(value):
        # Ensure that the value is within the valid range for an int64_t
        if not (-0x8000000000000000 <= value <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError("Value is not within the valid range for int64_t")

        # Define the format string for struct.pack
        fmt = "<q"  # q represents an 8-byte signed integer (int64_t) in little-endian byte order

        # Pack the value into a binary string
        int64_t_bytes = struct.pack(fmt, value)

        return int64_t_bytes

    @staticmethod
    def int_to_uint16_t(value):
        # Ensure that the value is within the valid range for a uint16_t
        if not (0 <= value <= 0xFFFF):
            raise ValueError("Value is not within the valid range for uint16_t")

        # Define the format string for struct.pack
        fmt = ">H"  # H represents a 2-byte unsigned integer (uint16_t) in little-endian byte order

        # Pack the value into a binary string
        uint16_t_bytes = struct.pack(fmt, value)

        return uint16_t_bytes

    @staticmethod
    def int_to_int16_t(value):
        # Ensure that the value is within the valid range for an int16_t
        if not (-0x8000 <= value <= 0x7FFF):
            raise ValueError("Value is not within the valid range for int16_t")

        # Define the format string for struct.pack
        fmt = ">h"  # h represents a 2-byte signed integer (int16_t) in little-endian byte order

        # Pack the value into a binary string
        int16_t_bytes = struct.pack(fmt, value)

        return int16_t_bytes

    @staticmethod
    def int_to_compactSize_t(value):
        if 0 <= value <= 252:
            return bytes([value])
        elif 253 <= value <= 0xFFFF:
            return b'\xfd' + value.to_bytes(2, byteorder='little')
        elif 0x10000 <= value <= 0xFFFFFFFF:
            return b'\xfe' + value.to_bytes(4, byteorder='little')
        elif 0x100000000 <= value <= 0xFFFFFFFFFFFFFFFF:
            return b'\xff' + value.to_bytes(8, byteorder='little')
        else:
            raise ValueError("Value is out of range for compactSize")

    def unmarshal_compactsize(self, b):
        key = b[0]
        if key == 0xff:
            return b[0:9], self.unmarshal_uint(b[1:9])
        if key == 0xfe:
            return b[0:5], self.unmarshal_uint(b[1:5])
        if key == 0xfd:
            return b[0:3], self.unmarshal_uint(b[1:3])
        return b[0:1], self.unmarshal_uint(b[0:1])

    def bool_t(self, flag: bool):
        return self.uint8_t(1 if flag else 0)

    @staticmethod
    def uint8_t(n):
        return int(n).to_bytes(1, byteorder='little', signed=False)

    @staticmethod
    def uint16_t(n, byteorder='little'):
        return int(n).to_bytes(2, byteorder=sys.byteorder, signed=False)

    @staticmethod
    def int32_t(n):
        return int(n).to_bytes(4, byteorder='little', signed=True)

    @staticmethod
    def uint32_t(n):
        return int(n).to_bytes(4, byteorder='little', signed=False)

    @staticmethod
    def int64_t(n):
        return int(n).to_bytes(8, byteorder='little', signed=True)

    @staticmethod
    def uint64_t(n):
        return int(n).to_bytes(8, byteorder='little', signed=False)

    @staticmethod
    def ipv4_to_ipv6(ipv4_address):
        # Validate the input as a valid IPv4 address
        try:
            ipv4_address = ipaddress.IPv4Address(ipv4_address)
        except ipaddress.AddressValueError as e:
            raise ValueError(f"Invalid IPv4 address: {e}")

        # Convert the IPv4 address to its IPv6 representation
        ipv6_address = ipaddress.IPv6Address(f"::ffff:{ipv4_address}")

        # convert ipv6 into hex, with 0 prefixed padding
        ipv6_mapped_bytes = ipv6_address.packed

        return ipv6_mapped_bytes

    @staticmethod
    def ipv6_from_ipv4(ipv4_str):
        pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
        return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))

    @staticmethod
    def ipv6_to_ipv4(ipv6):
        return '.'.join([str(b) for b in ipv6[12:]])


if __name__ == '__main__':
    """
    This program has a hardcoded listening address for the peer node.
    It works perfectly with nodes that are running version 70016.

    Usage: python lab5.py

    :param sys.argv (list): Command-line arguments provided when running the script.
    :raises SystemExit: Exits the program if the correct number of arguments is not provided.
    """
    lab5 = Lab5()

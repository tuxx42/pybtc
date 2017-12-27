import socket
from time import time
import threading
import queue
import fcntl
import os
import random

from scapy.all import interact
import bitcoin


VERSION = 70013
USER_AGENT = bitcoin.VarStrPktField(data='/Satoshi:0.14.2/')

transactions = {}
KNOWN = 'verack', 'version'


class ClientCommand:
    CMD_GETADDR = 'getaddr'
    STOP = 'stop'
    ADDR = 'addr'
    VERSION = 'vers'
    VERACK = 'verack'
    RECEIVE = 'receive'
    PING = 'ping'
    GETADDR = 'getaddr'
    TX = 'tx'
    INV = 'inv'


class BitcoinClient(threading.Thread):
    def __init__(self, ip, port, cmd_q=None):
        super(BitcoinClient, self).__init__()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = ip
        self.port = port
        self.socket = sock
        self.cmd_q = cmd_q or queue.Queue()
        self.alive = threading.Event()
        self.alive.set()
        self.nonce = random.randrange(0, 0xFFFFFFFFFFFFFFFF)
        self.stop = False
        self.addresses = []

        self.handlers = {
            ClientCommand.VERSION: self.handle_VERSION,
            ClientCommand.CMD_GETADDR: self.handle_GETADDR,
            ClientCommand.VERACK: self.handle_VERACK,
            ClientCommand.INV: self.handle_INV,
            ClientCommand.PING: self.handle_PING,
            ClientCommand.TX: self.handle_TX,
            ClientCommand.ADDR: self.handle_ADDR,
            ClientCommand.STOP: self.handle_STOP
        }

    def run(self):
        self.socket.connect((self.ip, self.port))
        fcntl.fcntl(self.socket, fcntl.F_SETFL, os.O_NONBLOCK)
        data = b''
        n = 24
        self.handle_VERSION()
        while self.alive.isSet() and not self.stop:
            if len(data) < n:
                try:
                    chunk = self.socket.recv(n - len(data))
                    if chunk == b'':
                        print('received EOF')
                        self.socket.close()
                        break

                    data += chunk
                except socket.error:
                    pass

            if len(data) == n:
                self.handle_HEADER_RECEIVED(data)
                data = b''

            try:
                cmd = self.cmd_q.get(block=True, timeout=0.3)
                if len(cmd) > 1:
                    cmd, args = cmd
                else:
                    args = ()

                self.handlers[cmd](*args)
            except queue.Empty as e:
                continue

    def cmd(self, cmd, *args):
        self.cmd_q.put((cmd, args))

    def join(self, timeout=None):
        self.alive.clear()
        threading.Thread.join(self, timeout)

    def message_version(self, arg):
        addr_from = bitcoin.AddrWithoutTimePktField(addr='::', port=0)
        addr_recv = bitcoin.AddrWithoutTimePktField(
            addr=self.ip, port=self.port)

        version_message = bitcoin.BitcoinVersion(
            version=70015,
            nonce=self.nonce,
            addr_from=addr_from,
            addr_recv=addr_recv,
            timestamp=int(time()),
            user_agent=USER_AGENT,
            relay=1
            # LELongEnumField("services",0, SERVICES_TYPES),
        )

        bitcoin_hdr = bitcoin.BitcoinHdr()
        bitcoin_hdr.add_payload(version_message)
        bitcoin_hdr.build()

        return bitcoin_hdr

    def message_verack(self):
        return bitcoin.BitcoinHdr(cmd='verack')

    def message_pong(self):
        return bitcoin.BitcoinPong(nonce=self.nonce)

    def handle_STOP(self, arg):
        self.stop = True

    def message_getdata(self, message):
        for i in message.payload.inventory:
            if i.hash in transactions:
                print('hash {} ALREADY KNOWN'.format(i.hash))
                print('hash {} ALREADY KNOWN'.format(i.hash))
                print('hash {} ALREADY KNOWN'.format(i.hash))
                print('hash {} ALREADY KNOWN'.format(i.hash))
        inventory = [i for i in message.payload.inventory
                     if i.hash not in transactions]
        txlist = inventory
        inv_message = bitcoin.BitcoinGetdata(
            count=len(txlist), inventory=txlist)
        inv_message.build()

        bitcoin_hdr = bitcoin.BitcoinHdr(cmd='getdata')
        bitcoin_hdr.add_payload(inv_message)
        bitcoin_hdr.build()

        return bitcoin_hdr

    def message_getaddr(self, arg):
        return bitcoin.BitcoinHdr(cmd='getaddr')

    def handle_INV(self, message):
        message = self.message_getdata(message)
        message.show()
        self.send_message(message)

    def handle_GETADDR(self, arg):
        message = self.message_getaddr(arg)
        self.send_message(message)

    def handle_VERSION(self, arg=None):
        message = self.message_version(arg)
        # message.show()
        self.send_message(message)

    def handle_VERACK(self, arg):
        message = self.message_verack()
        # message.show()
        self.send_message(message)
        message = self.message_getaddr(None)
        self.send_message(message)

    def handle_PING(self, arg):
        pong_message = self.message_pong()
        bitcoin_hdr = bitcoin.BitcoinHdr(cmd='pong')
        bitcoin_hdr.add_payload(pong_message)
        bitcoin_hdr.build()

        # XXX borken
        # self.send_message(pong_message)

    def handle_TX(self, arg):
        s = arg.tx_in[0].hash
        txhash = ''.join(['{:02x}'.format(i) for i in s[::-1]])
        transactions[txhash] = True

    def handle_ADDR(self, message):
        self.addresses = [(addr.addr, addr.port)
                          for addr in message.payload.addr_list]

    def handle_HEADER_RECEIVED(self, header_data):
        msg_header = bitcoin.BitcoinHdr(header_data)
        buf = self._recv_n_bytes(msg_header.len)
        if len(buf) != msg_header.len:
            print('buf is ont {} bytes'.format(msg_header.len))
            return
        message = bitcoin.BitcoinHdr(header_data + buf)
        self.last_message = message
        message.show()

        if message.cmdstr in self.handlers:
            self.handlers[message.cmdstr](message)

        return message

    def send_message(self, message):
        print('sending')
        message.show()
        self.socket.sendall(bytes(message))

    def _recv_n_bytes(self, n):
        data = b''
        while len(data) < n:
            try:
                chunk = self.socket.recv(n - len(data))
                if chunk == '':
                    break
                data += chunk
            except BlockingIOError:
                pass
        return data


if __name__ == '__main__':
    client = BitcoinClient(ip='::ffff:217.248.23.25', port=8333)
    # client.start()

    interact(mydict=globals(),
             mybanner='Type "client.start()" to start the client')

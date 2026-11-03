"""Small, intentionally unprotected conveyor PLC on IPv4 loopback only.

Register 0 = run command, 1 = speed percentage, 2 = illustrative position.
This is a software process model, not a real PLC runtime or validated physics.
"""
import socketserver
import struct
import threading
import time
from .protocol import Stream, ProtocolError, decode, frame


class Conveyor:
    def __init__(self):
        self.registers = [0, 0, 0]
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def execute(self, request):
        with self.lock:
            now = time.monotonic()
            self.registers[2] = (self.registers[2] + int((now - self.last) * self.registers[0] * self.registers[1] * 10)) % 65536
            self.last = now
            if request.unit != 1:
                return bytes([request.function | 128, 11])
            limit = 3 if request.function == 3 else 2
            if request.address + request.quantity > limit:
                return bytes([request.function | 128, 2])
            if request.function == 3:
                values = self.registers[request.address:request.address + request.quantity]
                return bytes([3, len(values) * 2]) + struct.pack('!' + 'H' * len(values), *values)
            # Deliberately accepts out-of-policy values: detector observes, not enforces.
            self.registers[request.address:request.address + request.quantity] = request.values
            if request.function == 6:
                return struct.pack('!BHH', 6, request.address, request.values[0])
            return struct.pack('!BHH', 16, request.address, request.quantity)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        stream = Stream()
        self.request.settimeout(3)
        try:
            while data := self.request.recv(4096):
                for raw in stream.feed(data):
                    try:
                        request = decode(raw)
                        pdu = self.server.conveyor.execute(request)
                    except ProtocolError:
                        pdu = bytes([raw[7] | 128, 1])
                    transaction, _, _, unit = struct.unpack('!HHHB', raw[:7])
                    self.request.sendall(frame(transaction, unit, pdu))
        except (OSError, ProtocolError):
            return


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        self.conveyor = Conveyor()
        # Not configurable: milestone one cannot bind a non-loopback interface.
        super().__init__(('127.0.0.1', 0), Handler)

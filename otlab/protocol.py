"""Bounded Modbus TCP framing and strict FC03/FC06/FC16 request decoding.

Reference: https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf
Addresses are zero based. This is a deliberately limited protocol implementation.
"""
import struct
from dataclasses import dataclass


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Request:
    transaction: int
    unit: int
    function: int
    address: int
    quantity: int
    values: tuple[int, ...] = ()


def frame(transaction, unit, pdu):
    if not 1 <= len(pdu) <= 253:
        raise ProtocolError('PDU length outside 1..253')
    return struct.pack('!HHHB', transaction, 0, len(pdu) + 1, unit) + pdu


class Stream:
    """Reassemble application frames from ordered TCP socket bytes.

    Not a PCAP TCP sequence-number reassembler. A malformed stream is terminal.
    """
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        frames = []
        while len(self.buffer) >= 6:
            _, protocol, length = struct.unpack('!HHH', self.buffer[:6])
            if protocol != 0 or not 2 <= length <= 254:
                self.buffer.clear()
                raise ProtocolError('Invalid MBAP protocol or length')
            size = 6 + length
            if len(self.buffer) < size:
                break
            frames.append(bytes(self.buffer[:size]))
            del self.buffer[:size]
        return frames

    def finish(self):
        if self.buffer:
            raise ProtocolError('Truncated Modbus frame at stream end')


def decode(raw):
    if len(raw) < 8:
        raise ProtocolError('Truncated ADU')
    transaction, protocol, length, unit = struct.unpack('!HHHB', raw[:7])
    if protocol or not 2 <= length <= 254 or len(raw) != length + 6:
        raise ProtocolError('Invalid ADU envelope')
    pdu = raw[7:]
    function = pdu[0]
    if function in (3, 6):
        if len(pdu) != 5:
            raise ProtocolError('FC03/FC06 request must have five PDU bytes')
        address, value = struct.unpack('!HH', pdu[1:])
        if function == 3:
            if not 1 <= value <= 125 or address + value > 65536:
                raise ProtocolError('Invalid read range')
            return Request(transaction, unit, function, address, value)
        return Request(transaction, unit, function, address, 1, (value,))
    if function == 16:
        if len(pdu) < 6:
            raise ProtocolError('Truncated FC16 request')
        address, quantity, count = struct.unpack('!HHB', pdu[1:6])
        if (not 1 <= quantity <= 123 or count != quantity * 2
                or len(pdu) != 6 + count or address + quantity > 65536):
            raise ProtocolError('Invalid FC16 quantity, byte count, or range')
        values = struct.unpack('!' + 'H' * quantity, pdu[6:])
        return Request(transaction, unit, function, address, quantity, values)
    raise ProtocolError(f'Unsupported function {function}; not classified as benign')


def response_status(request, raw):
    if len(raw) < 8:
        return 'invalid_response'
    transaction, protocol, length, unit = struct.unpack('!HHHB', raw[:7])
    if (transaction != request.transaction or protocol or unit != request.unit
            or not 2 <= length <= 254 or len(raw) != length + 6):
        return 'invalid_response'
    pdu = raw[7:]
    if pdu[0] == (request.function | 128):
        return 'server_exception' if len(pdu) == 2 and pdu[1] != 0 else 'invalid_response'
    if pdu[0] != request.function:
        return 'invalid_response'
    if request.function == 6:
        expected = struct.pack('!BHH', 6, request.address, request.values[0])
        return 'acknowledged' if pdu == expected else 'invalid_response'
    if request.function == 16:
        expected = struct.pack('!BHH', 16, request.address, request.quantity)
        return 'acknowledged' if pdu == expected else 'invalid_response'
    if len(pdu) == 2 + request.quantity * 2 and pdu[1] == request.quantity * 2:
        return 'read_response'
    return 'invalid_response'

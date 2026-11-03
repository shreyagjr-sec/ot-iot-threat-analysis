import json
from pathlib import Path
import unittest
from otlab.protocol import Stream, ProtocolError, decode, response_status
from otlab.policy import evaluate, validate
from otlab.simulator import Conveyor


class ProtocolTests(unittest.TestCase):
    # Literal bytes, independent of the project's frame encoder.
    WRITE = bytes.fromhex('000100000006010600010064')

    def test_every_split_and_coalesced_frames(self):
        for split in range(1, len(self.WRITE)):
            stream = Stream()
            self.assertEqual(stream.feed(self.WRITE[:split]), [])
            self.assertEqual(stream.feed(self.WRITE[split:] + self.WRITE), [self.WRITE, self.WRITE])
            stream.finish()

    def test_truncated_stream(self):
        stream = Stream()
        stream.feed(self.WRITE[:-1])
        with self.assertRaises(ProtocolError):
            stream.finish()

    def test_invalid_envelopes(self):
        for raw in ('000100010006010600010064', '00010000000101', '00010000ffff0106'):
            with self.assertRaises(ProtocolError):
                Stream().feed(bytes.fromhex(raw))

    def test_fc16_count_and_range(self):
        valid = decode(bytes.fromhex('00010000000b0110000000020400010064'))
        self.assertEqual(valid.values, (1, 100))
        for raw in ('00010000000b0110000000020200010064',
                    '00010000000b0110ffff00020400010064'):
            with self.assertRaises(ProtocolError):
                decode(bytes.fromhex(raw))

    def test_unknown_function_is_not_clean(self):
        with self.assertRaises(ProtocolError):
            decode(bytes.fromhex('000100000006011600010064'))

    def test_response_correlation(self):
        request = decode(self.WRITE)
        self.assertEqual(response_status(request, self.WRITE), 'acknowledged')
        self.assertEqual(response_status(request, bytes.fromhex('000100000003018602')), 'server_exception')
        self.assertEqual(response_status(request, bytes.fromhex('000200000006010600010064')), 'invalid_response')
        self.assertEqual(response_status(request, bytes.fromhex('000100000006010600010063')), 'invalid_response')


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = validate(json.loads((Path(__file__).resolve().parents[1] / 'config/conveyor-policy.json').read_text()))

    def test_source_and_bounds_independently(self):
        for value, source, expected in ((0, '127.0.0.2', []), (100, '127.0.0.2', []),
                                        (101, '127.0.0.2', ['out_of_range']),
                                        (50, '127.0.0.3', ['unapproved_source']),
                                        (101, '127.0.0.3', ['unapproved_source', 'out_of_range'])):
            raw = bytes.fromhex('00010000000601060001') + value.to_bytes(2, 'big')
            self.assertEqual(evaluate(decode(raw), source, self.policy)['reasons'], expected)

    def test_exception_does_not_erase_attempt(self):
        request = decode(bytes.fromhex('000100000006010600020001'))
        self.assertEqual(evaluate(request, '127.0.0.2', self.policy)['reasons'], ['register_not_allowed'])
        self.assertEqual(Conveyor().execute(request), bytes.fromhex('8602'))

    def test_unknown_unit_is_unassessed(self):
        request = decode(bytes.fromhex('000100000006020600010064'))
        self.assertEqual(evaluate(request, '127.0.0.2', self.policy)['verdict'], 'unassessed')

    def test_read_is_not_write(self):
        request = decode(bytes.fromhex('000100000006010300000002'))
        self.assertEqual(evaluate(request, '127.0.0.3', self.policy)['verdict'], 'not_a_write')

    def test_simulator_accepts_bad_speed_for_detection(self):
        conveyor = Conveyor()
        request = decode(bytes.fromhex('0001000000060106000100c8'))
        self.assertEqual(conveyor.execute(request), bytes.fromhex('06000100c8'))
        self.assertEqual(conveyor.registers[1], 200)


if __name__ == '__main__':
    unittest.main()

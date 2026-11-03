import json
from pathlib import Path
import tempfile
import unittest
from otlab.storage import Store
from otlab.streaming import process_value


class MessageValidationTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        temp_root = root / 'runtime/test-temp'
        temp_root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temp_root)
        policy = json.loads((root / 'config/conveyor-policy.json').read_text())
        self.store = Store(Path(self.temp.name) / 'db.sqlite3', policy)

    def tearDown(self):
        self.temp.cleanup()

    def test_poison_messages_do_not_write_findings(self):
        for payload in (b'{bad json', b'[]', b'null', b'x' * 16385,
                        b'{"finding":"clean"}', b'{"event_id":"x"}'):
            with self.assertRaises((ValueError, KeyError, TypeError)):
                process_value(payload, self.store)
        self.assertEqual(self.store.list(), [])

    def test_delivered_retry_is_idempotent(self):
        raw = json.dumps({'event_id': 'retry', 'source': '127.0.0.3',
                          'request_hex': '0001000000060106000100c8',
                          'response_hex': None, 'evidence_kind': 'application_instrumented'}).encode()
        first, created = process_value(raw, self.store)
        self.assertTrue(created)
        again, created = process_value(raw, self.store)
        self.assertFalse(created)
        self.assertEqual(first, again)
        self.assertEqual(first['finding']['verdict'], 'policy_violation')

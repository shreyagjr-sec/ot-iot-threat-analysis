import json
from pathlib import Path
import tempfile
import unittest
from otlab.storage import Store, EvidenceConflict
from otlab.protocol import ProtocolError


class StorageTests(unittest.TestCase):
    def setUp(self):
        temp_root = Path(__file__).resolve().parents[1] / 'runtime/test-temp'
        temp_root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temp_root)
        self.path = Path(self.temp.name) / 'findings.sqlite3'
        self.policy = json.loads((Path(__file__).resolve().parents[1] / 'config/conveyor-policy.json').read_text())
        self.store = Store(self.path, self.policy)
        self.evidence = dict(event_id='test:1', source='127.0.0.3',
                             request_hex='0001000000060106000100c8',
                             response_hex='0001000000060106000100c8',
                             evidence_kind='application_instrumented')

    def tearDown(self):
        self.temp.cleanup()

    def test_persistence_and_retry(self):
        result, created = self.store.ingest(self.evidence)
        self.assertTrue(created)
        self.assertEqual(result['finding']['reasons'], ['unapproved_source', 'out_of_range'])
        reopened = Store(self.path, self.policy)
        repeated, created = reopened.ingest(self.evidence)
        self.assertFalse(created)
        self.assertEqual(result, repeated)
        self.assertEqual(len(reopened.list()), 1)

    def test_conflicting_evidence_is_not_overwritten(self):
        self.store.ingest(self.evidence)
        with self.assertRaises(EvidenceConflict):
            self.store.ingest({**self.evidence, 'source': '127.0.0.2'})
        self.assertEqual(self.store.list()[0]['source'], '127.0.0.3')

    def test_policy_change_requires_new_event_id(self):
        self.store.ingest(self.evidence)
        self.policy['registers']['1'] = [0, 200]
        with self.assertRaises(EvidenceConflict):
            Store(self.path, self.policy).ingest(self.evidence)

    def test_malformed_evidence_not_persisted(self):
        for change in ({'request_hex': 'zz'}, {'source': 'not-an-ip'},
                       {'request_hex': '000100000006011600010064'}):
            with self.assertRaises((ValueError, ProtocolError)):
                self.store.ingest({**self.evidence, **change})
        self.assertEqual(self.store.list(), [])

    def test_missing_response_is_not_success(self):
        result, _ = self.store.ingest({**self.evidence, 'response_hex': None})
        self.assertEqual(result['response_status'], 'not_observed')


if __name__ == '__main__':
    unittest.main()

"""
Unit tests for Analyst Notes markdown parsing, references, mentions, and version history.
"""

import unittest
from netfusion_workflow import WorkflowService


class TestAnalystNotes(unittest.TestCase):
    def setUp(self):
        self.service = WorkflowService()
        self.inv = self.service.create_investigation(title="Note Test Investigation")

    def test_add_note_with_references_and_mentions(self):
        note = self.service.add_note(
            investigation_id=self.inv.investigation_id,
            title="Analysis of C2 Traffic",
            content="""
# Technical Observation

Observed outbound requests to `http://malicious-domain.com/c2`.

```python
import socket
s = socket.socket()
```

cc @lead_analyst for review.
            """,
            author="analyst_dave",
            ioc_references=["192.168.1.100", "malicious-domain.com"],
            mitre_references=["T1071.001"],
            mentions=["lead_analyst"],
        )

        self.assertEqual(note.title, "Analysis of C2 Traffic")
        self.assertEqual(len(note.ioc_references), 2)
        self.assertEqual(len(note.mitre_references), 1)
        self.assertIn("lead_analyst", note.mentions)
        self.assertEqual(len(note.version_history), 1)
        self.assertEqual(note.version_history[0].version_number, 1)


if __name__ == "__main__":
    unittest.main()

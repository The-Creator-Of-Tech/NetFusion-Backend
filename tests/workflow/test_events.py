"""
Unit tests for Workflow Event Publisher and listeners.
"""

import unittest
from netfusion_workflow import (
    WorkflowEventPublisher,
    CaseCreated,
    InvestigationStarted,
    EvidenceAdded,
    StatusChanged,
)


class TestWorkflowEvents(unittest.TestCase):
    def test_event_publishing_and_listener(self):
        received_events = []

        def listener(evt):
            received_events.append(evt)

        publisher = WorkflowEventPublisher(listener_callback=listener)

        evt1 = CaseCreated(case_id="c-1", title="Case 1")
        evt2 = InvestigationStarted(investigation_id="inv-1", title="Inv 1")
        evt3 = EvidenceAdded(evidence_id="ev-1", investigation_id="inv-1", name="sample.exe")

        publisher.publish(evt1)
        publisher.publish(evt2)
        publisher.publish(evt3)

        self.assertEqual(len(received_events), 3)
        self.assertEqual(received_events[0].event_type, "CaseCreated")
        self.assertEqual(received_events[1].event_type, "InvestigationStarted")
        self.assertEqual(received_events[2].event_type, "EvidenceAdded")


if __name__ == "__main__":
    unittest.main()

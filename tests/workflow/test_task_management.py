"""
Unit tests for Task Management and Task Dependency Rules.
"""

import unittest
from netfusion_workflow import (
    WorkflowService,
    TaskStatus,
    Priority,
    TaskDependencyError,
    EntityNotFoundError,
)


class TestTaskManagement(unittest.TestCase):
    def setUp(self):
        self.service = WorkflowService()
        self.inv = self.service.create_investigation(title="Task Test Investigation")

    def test_create_and_complete_task(self):
        task = self.service.create_task(
            investigation_id=self.inv.investigation_id,
            title="Inspect memory dump",
            assignee="analyst_bob",
            priority=Priority.HIGH,
        )
        self.assertEqual(task.status, TaskStatus.TODO)

        updated = self.service.update_task_status(
            investigation_id=self.inv.investigation_id,
            task_id=task.task_id,
            new_status=TaskStatus.COMPLETED,
            actor="analyst_bob",
        )
        self.assertEqual(updated.status, TaskStatus.COMPLETED)
        self.assertEqual(updated.completion_percentage, 100.0)
        self.assertIsNotNone(updated.completed_at)
        self.assertEqual(updated.completed_by, "analyst_bob")

    def test_task_dependencies_enforced(self):
        task1 = self.service.create_task(
            investigation_id=self.inv.investigation_id,
            title="Task 1 - Isolate Network",
        )
        task2 = self.service.create_task(
            investigation_id=self.inv.investigation_id,
            title="Task 2 - Dump RAM",
            dependencies=[task1.task_id],
        )

        # Attempting to complete Task 2 before Task 1 completes must fail
        with self.assertRaises(TaskDependencyError):
            self.service.update_task_status(
                investigation_id=self.inv.investigation_id,
                task_id=task2.task_id,
                new_status=TaskStatus.COMPLETED,
            )

        # Complete Task 1 first
        self.service.update_task_status(
            investigation_id=self.inv.investigation_id,
            task_id=task1.task_id,
            new_status=TaskStatus.COMPLETED,
        )

        # Now Task 2 can be completed
        updated2 = self.service.update_task_status(
            investigation_id=self.inv.investigation_id,
            task_id=task2.task_id,
            new_status=TaskStatus.COMPLETED,
        )
        self.assertEqual(updated2.status, TaskStatus.COMPLETED)

    def test_invalid_task_id_raises_not_found(self):
        with self.assertRaises(EntityNotFoundError):
            self.service.update_task_status(
                investigation_id=self.inv.investigation_id,
                task_id="nonexistent-id",
                new_status=TaskStatus.IN_PROGRESS,
            )


if __name__ == "__main__":
    unittest.main()

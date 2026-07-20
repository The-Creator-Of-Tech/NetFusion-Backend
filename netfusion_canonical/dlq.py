import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DLQMessage:
    message_id: str
    raw_payload: Any
    errors: List[str]
    collector_id: str
    execution_id: str
    timestamp: float = field(default_factory=time.time)


class DeadLetterQueue:
    """Dead Letter Queue (DLQ) for collecting rejected invalid objects and audit trails."""

    def __init__(self):
        self.messages: List[DLQMessage] = []

    def enqueue(
        self, raw_payload: Any, errors: List[str], collector_id: str, execution_id: str
    ) -> DLQMessage:
        msg_id = f"dlq-{len(self.messages) + 1:06d}-{int(time.time())}"
        msg = DLQMessage(
            message_id=msg_id,
            raw_payload=raw_payload,
            errors=errors,
            collector_id=collector_id,
            execution_id=execution_id,
        )
        self.messages.append(msg)
        return msg

    def get_messages(self) -> List[DLQMessage]:
        return self.messages

    def clear(self) -> None:
        self.messages.clear()

from typing import Any, List, Optional
from .base import CanonicalDomainObject
from .validator import CanonicalValidator
from .dlq import DeadLetterQueue


class NormalizationPipeline:
    """
    Normalization Engine Pipeline handling validation, cryptographic sealing,
    and DLQ routing for canonical objects.
    """

    def __init__(self, dlq: Optional[DeadLetterQueue] = None):
        self.validator = CanonicalValidator()
        self.dlq = dlq or DeadLetterQueue()
        self.validated_objects: List[CanonicalDomainObject] = []

    def process_object(self, obj: Any, context: Any) -> bool:
        if not isinstance(obj, CanonicalDomainObject):
            self.dlq.enqueue(
                raw_payload=str(obj),
                errors=["Object does not inherit from CanonicalDomainObject"],
                collector_id=getattr(context, "collector_id", "unknown"),
                execution_id=getattr(context, "execution_id", "unknown"),
            )
            return False

        is_valid, errors = self.validator.validate(obj)
        if is_valid:
            self.validated_objects.append(obj)
            return True
        else:
            self.dlq.enqueue(
                raw_payload=obj.to_dict(),
                errors=errors,
                collector_id=getattr(context, "collector_id", obj.collector_id),
                execution_id=getattr(context, "execution_id", obj.correlation_id),
            )
            return False

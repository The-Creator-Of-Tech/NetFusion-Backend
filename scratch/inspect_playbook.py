import sys
import os
import json

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.workflow_execution_service import _PLAYBOOK_STORE

pb = _PLAYBOOK_STORE.get("578097a7-5542-577b-9e2d-e5738eb3a2f2")
print(json.dumps(pb, indent=2))

"""
Root test runner for netfusion_intelligence.
"""

import pytest

# pytest_plugins is automatically imported when discovering netfusion_intelligence tests
# pytest_plugins = ["netfusion_intelligence.tests.conftest"]

from netfusion_intelligence.tests.test_engine import *
from netfusion_intelligence.tests.test_registry import *
from netfusion_intelligence.tests.test_scheduler import *
from netfusion_intelligence.tests.test_versioning import *
from netfusion_intelligence.tests.test_validation import *
from netfusion_intelligence.tests.test_rollback import *
from netfusion_intelligence.tests.test_health import *
from netfusion_intelligence.tests.test_repository import *
from netfusion_intelligence.tests.test_events import *
from netfusion_intelligence.tests.test_api import *

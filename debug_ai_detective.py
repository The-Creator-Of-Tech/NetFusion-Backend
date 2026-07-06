import os
import sys
import traceback
sys.path.insert(0, os.getcwd())
from main import ai_detective

data = {'projectId': 'test_project', 'question': 'How many packets were captured?'}
try:
    result = ai_detective(data)
    print('RESULT:', result)
except Exception:
    traceback.print_exc()

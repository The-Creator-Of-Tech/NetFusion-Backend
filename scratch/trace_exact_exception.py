import sys
import os
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import capture_service

interface = r"\Device\NPF_{55969DAD-01B7-45E2-B14A-9E299B234297} (Wi-Fi)"

print("1. Calling start_capture...")
try:
    start_res = capture_service.start_capture(interface)
    print("start_capture returned:", start_res)
except Exception as e:
    import traceback
    print("start_capture failed with exception:")
    traceback.print_exc()

print("\nSleeping for 5 seconds...")
time.sleep(5)

print("\n2. Calling stop_capture...")
try:
    stop_res = capture_service.stop_capture()
    print("stop_capture returned:", stop_res)
except Exception as e:
    import traceback
    print("stop_capture failed with exception:")
    traceback.print_exc()

print("\n3. Calling analyze_latest_capture...")
try:
    analyze_res = capture_service.analyze_latest_capture()
    print("analyze_latest_capture returned:", analyze_res)
except Exception as e:
    import traceback
    print("analyze_latest_capture failed with exception:")
    traceback.print_exc()

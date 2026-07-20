import subprocess
import sys
import time
import unittest
from netfusion_collector_sdk.subprocess_runner import SubprocessRunner


class TestTimeoutCancellation(unittest.TestCase):

    def test_subprocess_timeout_enforcement(self):
        # Python script that sleeps for 10 seconds
        cmd = [sys.executable, "-c", "import time; time.sleep(10)"]
        start_time = time.time()

        with self.assertRaises(subprocess.TimeoutExpired):
            SubprocessRunner.run_cmd(cmd=cmd, timeout=1)

        elapsed = time.time() - start_time
        self.assertLess(elapsed, 4.0)

    def test_subprocess_cancel_process(self):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        self.assertIsNone(proc.poll())

        SubprocessRunner.cancel_process(proc, timeout_sec=0.5)
        self.assertIsNotNone(proc.poll())


if __name__ == "__main__":
    unittest.main()

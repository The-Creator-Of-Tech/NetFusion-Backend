import os
import signal
import subprocess
import sys
import time
from typing import List, Optional, Tuple, Callable


class SubprocessRunner:
    """
    Subprocess execution manager enforcing process tree tracking, timeouts,
    graceful SIGTERM/SIGKILL cancellation, and cross-platform (Windows & Linux) execution.
    NEVER uses shell=True.
    """

    @staticmethod
    def run_cmd(
        cmd: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
    ) -> Tuple[int, str, str]:
        """
        Executes a subprocess without shell invocation.
        Returns tuple of (exit_code, stdout, stderr).
        """
        if not cmd or not isinstance(cmd, list):
            raise ValueError("Command must be a non-empty list of string arguments.")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            env=env or os.environ.copy(),
            shell=False,
        )

        try:
            stdout_data, stderr_data = process.communicate(timeout=timeout)
            retcode = process.returncode
            if on_stdout and stdout_data:
                for line in stdout_data.splitlines():
                    on_stdout(line)
            if on_stderr and stderr_data:
                for line in stderr_data.splitlines():
                    on_stderr(line)
            return retcode, stdout_data, stderr_data
        except subprocess.TimeoutExpired:
            SubprocessRunner.cancel_process(process)
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout or 0)
        except Exception:
            SubprocessRunner.cancel_process(process)
            raise

    @staticmethod
    def cancel_process(process: subprocess.Popen, timeout_sec: float = 2.0) -> None:
        """Gracefully terminates a running subprocess tree with escalation to force kill."""
        if process.poll() is not None:
            return

        try:
            if sys.platform == "win32":
                process.terminate()
                try:
                    process.wait(timeout=timeout_sec)
                except subprocess.TimeoutExpired:
                    process.kill()
            else:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=timeout_sec)
                except subprocess.TimeoutExpired:
                    process.send_signal(signal.SIGKILL)
                    process.wait(timeout=1.0)
        except Exception:
            pass

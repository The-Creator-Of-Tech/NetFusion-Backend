"""
NetFusion Retry Policy & Backoff Module
Exponential backoff with jitter and retry policy execution.
"""

import time
import random
import logging
from typing import Callable, Any, Type, Tuple, Optional
from functools import wraps

logger = logging.getLogger(__name__)


def retry_with_backoff(
    max_attempts: int = 3,
    initial_delay: float = 0.5,
    backoff_factor: float = 2.0,
    max_delay: float = 10.0,
    jitter: bool = True,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,)
):
    """
    Decorator that retries a function call on matching exceptions with exponential backoff.
    """
    def decorator(func: Callable):
        @wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay
            last_exception = None

            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    if attempt == max_attempts:
                        logger.warning("Max retry attempts (%d) reached for %s", max_attempts, func.__name__)
                        raise e

                    sleep_time = delay
                    if jitter:
                        sleep_time += random.uniform(0, sleep_time * 0.1)
                    sleep_time = min(sleep_time, max_delay)

                    logger.debug("Attempt %d failed with %s: retrying in %.2fs", attempt, type(e).__name__, sleep_time)
                    time.sleep(sleep_time)
                    delay *= backoff_factor

            if last_exception:
                raise last_exception

        return wrapper

    return decorator


def execute_with_retry(
    func: Callable,
    max_attempts: int = 3,
    initial_delay: float = 0.5,
    backoff_factor: float = 2.0,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    *args,
    **kwargs
) -> Any:
    """Helper function to execute a callable with retry policy without decorator syntax."""
    decorated = retry_with_backoff(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        backoff_factor=backoff_factor,
        retryable_exceptions=retryable_exceptions
    )(func)
    return decorated(*args, **kwargs)

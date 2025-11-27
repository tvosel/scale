import time
from typing import final


@final
class TokenBucketRateLimiter:
    """
    A simple token bucket rate limiter.

    This implementation uses the token bucket algorithm to control the rate of
    operations. It's useful for preventing resource abuse and ensuring fair
    usage in distributed systems.

    Attributes:
        capacity (int): The maximum number of tokens the bucket can hold.
        refill_rate (float): The rate at which tokens are added to the bucket
                             (tokens per second).
    """

    def __init__(self, capacity: int, refill_rate: float):
        """
        Initializes the TokenBucketRateLimiter.

        Args:
            capacity: The maximum number of tokens in the bucket.
            refill_rate: The number of tokens to add per second.
        """
        if capacity <= 0:
            raise ValueError("Capacity must be positive.")
        if refill_rate <= 0:
            raise ValueError("Refill rate must be positive.")

        self.capacity: float = float(capacity)
        self.refill_rate: float = refill_rate
        self._tokens: float = self.capacity
        self._last_refill_time: float = time.monotonic()

    def allow_request(self) -> bool:
        """
        Determines if a request should be allowed based on available tokens.

        This method refills the bucket based on the time elapsed since the last
        check and then checks if at least one token is available. If so, it
        consumes one token and returns True. Otherwise, it returns False.

        Returns:
            True if the request is allowed, False otherwise.
        """
        self._refill()

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def _refill(self) -> None:
        """
        Adds tokens to the bucket based on the elapsed time.
        """
        now = time.monotonic()
        time_passed = now - self._last_refill_time
        tokens_to_add = time_passed * self.refill_rate

        if tokens_to_add > 0:
            self._tokens = min(self.capacity, self._tokens + tokens_to_add)
            self._last_refill_time = now

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"capacity={self.capacity}, "
            f"refill_rate={self.refill_rate}, "
            f"tokens={self._tokens:.2f})"
        )

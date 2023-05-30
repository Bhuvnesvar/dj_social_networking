from functools import wraps
from math import floor

import time
import sys
import threading
from rest_framework.response import Response
from rest_framework import status

now = time.monotonic if hasattr(time, 'monotonic') else time.time


class RateLimitException(Exception):
    def __init__(self, message, period_remaining):
        super(RateLimitException, self).__init__(message)
        self.period_remaining = period_remaining


class RateLimitDecorator(object):

    def __init__(self, calls=15, period=900, clock=now, raise_on_limit=True):

        self.clamped_calls = max(1, min(sys.maxsize, floor(calls)))
        self.period = period
        self.clock = clock
        self.raise_on_limit = raise_on_limit

        # Initialise the decorator state.
        self.last_reset = clock()
        self.num_calls = 0

        # Add thread safety.
        self.lock = threading.RLock()

    def __call__(self, func):
        @wraps(func)
        def wrapper(*args, **kargs):
            with self.lock:
                period_remaining = self.__period_remaining()

                # If the time window has elapsed then reset.
                if period_remaining <= 0:
                    self.num_calls = 0
                    self.last_reset = self.clock()

                # Increase the number of attempts to call the function.
                self.num_calls += 1

                # If the number of attempts to call the function exceeds the
                # maximum then raise an exception.
                if self.num_calls > self.clamped_calls:
                    if self.raise_on_limit:
                        # raise RateLimitException('too many calls', period_remaining)
                        data = {'message': 'You can sent only 3 friend requests in 1 minute. Try after 1 minute.',
                                'status': status.HTTP_400_BAD_REQUEST}
                        return Response(data=data)
                    return

            return func(*args, **kargs)

        return wrapper

    def __period_remaining(self):

        elapsed = self.clock() - self.last_reset
        return self.period - elapsed


def sleep_and_retry(func):
    @wraps(func)
    def wrapper(*args, **kargs):
        while True:
            try:
                return func(*args, **kargs)
            except RateLimitException as exception:
                time.sleep(exception.period_remaining)

    return wrapper

import os
import time
from typing import List

class KeyValidator:
    CONSTANT_TIME_DELAY = 0.1  # 100ms constant delay

    def __init__(self):
        self.__valid_keys = list()
        for index in range(100):
            v = os.getenv(f"ONG_AUTH_VALID_API_KEY_{index}")
            if v:
                self.__valid_keys.append(v)


    def validate_key(self, key: str) -> bool:

        start_time = time.time()
        retval = key in self.__valid_keys
        if retval:
            return True
        # Calculate how much time has elapsed
        elapsed_time = time.time() - start_time

        # Always take at least CONSTANT_TIME_DELAY seconds
        # This masks the actual database query time
        remaining_time = self.CONSTANT_TIME_DELAY - elapsed_time
        if remaining_time > 0:
            time.sleep(remaining_time)
        return False
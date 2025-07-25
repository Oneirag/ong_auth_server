import os
from typing import List


def get_valid_api_keys() -> List[str]:
    """Return a list of valid (non-empty) api keys"""
    retval = list()
    for index in range(100):
        v = os.getenv(f"ONG_AUTH_VALID_API_KEY_{index}")
        if v:
            retval.append(v)
    return retval


def validate_key(key: str) -> bool:
    return key in get_valid_api_keys()
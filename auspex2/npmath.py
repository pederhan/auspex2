from typing import Any, Callable, Iterable, Union

import numpy as np
from loguru import logger

from .types import NumberType

_min = min
_max = max


def mean(a: Iterable[NumberType]) -> float:
    return _do_stats_math(np.mean, a)


def median(a: Iterable[NumberType]) -> float:
    return _do_stats_math(np.median, a)


def stdev(a: Iterable[NumberType]) -> float:
    return _do_stats_math(np.std, a)


def min(a: Iterable[Union[int, float]]) -> float:  # todo : fix type
    return _min(a, default=0.0)


def max(a: Iterable[Union[int, float]]) -> float:  # todo : fix type
    return _max(a, default=0.0)


def _do_stats_math(
    func: Callable[[Any], "np.number[Any]"],
    a: Iterable[NumberType],
    default: float = 0.0,
) -> float:
    """Wrapper function around numpy stats functions that handles exceptions and NaN."""
    try:
        res = func(a)
        if np.isnan(res):
            logger.debug(
                f"{func.__name__}({repr(a)}) returned nan. Defaulting to {default}"
            )
            return default
    except Exception as e:
        logger.error(f"{func.__name__}({repr(a)}) failed. Defaulting to {default}", e)
        return default
    return float(res)

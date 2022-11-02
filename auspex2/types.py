from collections import Counter
from numbers import Number, Real
from typing import Any, Iterable, Protocol, Union

import numpy as np
from harborapi.models.scanner import Severity, VulnerabilityItem
from numpy.typing import NDArray

# Represents a single RGBA color used by Matplotlib
MplRGBAColor = NDArray[np.float64]  # shape: (4,)

# Any number type we can pass to numpy
# NOTE: why does List[float] and List[int] not pass as List[Union[Number, Real]]
NumberType = Union[Number, Real, "np.number[Any]", float, int]


class ReportType(Protocol):
    """Interface for working with Harbor vulnerability reports.

    Defines a common interface for retrieving vulnerabilities regardless
    of whether the report is for a single artifact or an aggregate report."""

    @property
    def fixable(self) -> Iterable[VulnerabilityItem]:
        ...

    @property
    def unfixable(self) -> Iterable[VulnerabilityItem]:
        ...

    @property
    def critical(self) -> Iterable[VulnerabilityItem]:
        ...

    @property
    def high(self) -> Iterable[VulnerabilityItem]:
        ...

    @property
    def medium(self) -> Iterable[VulnerabilityItem]:
        ...

    @property
    def low(self) -> Iterable[VulnerabilityItem]:
        ...

    @property
    def distribution(self) -> "Counter[Severity]":
        ...

from abc import ABC, abstractmethod
from typing import Iterable, List, Union

from pydantic import BaseModel

from .plots import Plot
from .section import Section
from .tables import Table


# Maybe overkill to implement this as an ABC
class Layout(BaseModel, ABC):
    @property
    @abstractmethod
    def sections(self) -> Iterable[Section]:
        pass


class EmptyPage(Layout):
    @property
    def sections(self) -> Iterable[Section]:
        return []


class ReportLayout(Layout):
    stats_t: Table
    info_t: Table
    top_vulns_t: Table
    top_vulns_t_fix: Table
    vuln_p: List[Plot]  # maybe refactor

    @property
    def sections(self) -> Iterable[Section]:
        yield self.stats_t
        yield self.info_t
        yield from self.vuln_p
        yield self.top_vulns_t
        yield self.top_vulns_t_fix

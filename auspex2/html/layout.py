from typing import Iterable, List, Union

from pydantic import BaseModel

from ..plots import Plot
from ..tables import Table


class ReportLayout(BaseModel):
    stats_table: Table
    info_table: Table
    top_vulns_table: Table
    top_vulns_fix_table: Table
    vuln_plots: List[Plot]  # maybe refactor

    def layout(self) -> Iterable[Union[Table, Plot]]:
        yield self.stats_table
        yield self.info_table
        yield self.top_vulns_table
        yield self.top_vulns_fix_table
        yield from self.vuln_plots

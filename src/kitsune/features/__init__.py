"""AfterImage O(1) incremental feature extraction in R^100."""

from kitsune.features.afterimage import incStat, incStatDB
from kitsune.features.extractor import FE
from kitsune.features.netstat import netStat

__all__ = ["FE", "incStat", "incStatDB", "netStat"]

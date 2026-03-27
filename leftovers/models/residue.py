"""ResidueCandidate dataclass – a scored residue analysis result."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ResidueCandidate:
    type: str
    path: str
    mapped_path: str
    raw_score: int
    score: int
    reasons: List[str]
    first_seen: str
    last_seen: str
    processes: List[str]
    operations: List[str]
    exists_now: Optional[bool] = None
    status: str = "review"
    category: str = "functional"
    cluster: str = "uncategorized"
    removal_layer: str = "review_queue"
    installer_cluster_id: Optional[str] = None
    subtree_class: str = "none"
    rename_family_id: Optional[str] = None
    vendor_family_id: Optional[str] = None
    service_branch_id: Optional[str] = None
    root_family_id: Optional[str] = None
    cluster_membership_count: int = 0

"""Scoring configuration and persistence bonus constants."""

PERSISTENCE_BONUS = {
    "service": 22,
    "run_entry": 18,
    "scheduled_task": 20,
    "startup_shortcut": 16,
    "firewall_rule": 50,
}

SCORING_CONFIG = {
    "thresholds": {"safe_delete": 80, "review": 55, "minimum_include": 10},
    "persistence_bonus": {"service": 22, "run_entry": 18, "scheduled_task": 20, "startup_shortcut": 16, "firewall_rule": 50},
    "location_scores": {"appdata": 12, "programdata": 10, "program_files": 14, "hkcu_software": 16, "uninstall_key": 24, "current_version_run": 18},
    "provenance": {"first_creator_related": 45, "first_writer_related": 35, "exclusively_touched": 20, "written_by_chain_no_token": 35, "no_non_related_writes": 10, "installer_cache_related": 30, "guid_correlation": 40},
    "depth_boost": {"depth_0_1": 55, "depth_2_3": 40, "depth_4_plus": 25},
    "match_scores": {"path_match_base": 50, "path_extra_per_term": 5, "path_extra_max": 15, "detail_match": 20},
    "activity": {"write_0": -8, "write_1_2": 5, "write_3_9": 10, "write_10_plus": 15, "created": 10, "modified": 8, "read_only": -5},
    "session": {"non_related_writer_window": 10, "location_proximity": 25},
    "penalties": {"low_value_area": -45, "microsoft_path_no_token": -30, "generic_dir": -10},
    "traces": {"prefetch_trace": 15, "execution_trace": 15},
    "special": {"firewall_rule_reference": 50, "checked_only_residue": 12, "helper_process_default_boost": 20, "direct_chain_default_boost": 60},
    "cluster_bonus": {"threshold_4": 10, "threshold_7": 20, "threshold_10": 30},
    "fusion": {"types_3_bonus": 25, "types_4_bonus": 40},
    "subtree": {"subtree_only_or_first_bonus": 15},
    "expansion": {"neighborhood_min_score": 55, "survivor_min_score": 55, "registry_branch_min_score": 50, "sibling_min_score": 40, "confirmed_root_min_score": 80, "vendor_sweep_base_score": 45, "mirrored_root_score": 55},
}

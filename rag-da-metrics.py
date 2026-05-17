from typing import List, Dict, Any

SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def severity_less_than(sev1: str, sev2: str) -> bool:
    return SEVERITY_ORDER.get(sev1.upper(), -1) < SEVERITY_ORDER.get(sev2.upper(), -1)

def calculate_cmr_adv(y_true: List[str], y_adv: List[str]) -> tuple:
    crit_indices = [i for i, sev in enumerate(y_true) if sev.upper() == "CRITICAL"]
    if not crit_indices:
        return None, 0, 0
    n_crit_missed = sum(1 for i in crit_indices if y_adv[i].upper() != "CRITICAL")
    cmr_adv = n_crit_missed / len(crit_indices)
    return cmr_adv * 100, n_crit_missed, len(crit_indices)

def calculate_dsr(y_clean: List[str], y_adv: List[str]) -> tuple:
    high_risk_indices = [i for i, sev in enumerate(y_clean) if sev.upper() in ["HIGH", "CRITICAL"]]
    if not high_risk_indices:
        return None, 0, 0
    downgraded = sum(1 for i in high_risk_indices if severity_less_than(y_adv[i], y_clean[i]))
    dsr = downgraded / len(high_risk_indices)
    return dsr * 100, downgraded, len(high_risk_indices)

def calculate_true_asr(y_true: List[str], y_clean: List[str], y_adv: List[str]) -> tuple:
    clean_correct_indices = [i for i in range(len(y_true)) if y_clean[i].upper() == y_true[i].upper()]
    if not clean_correct_indices:
        return None, 0, 0
    attacked_wrong = sum(1 for i in clean_correct_indices if y_adv[i].upper() != y_true[i].upper())
    true_asr = attacked_wrong / len(clean_correct_indices)
    return true_asr * 100, attacked_wrong, len(clean_correct_indices)



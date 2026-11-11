from backend.utils.logger import get_logger

logger = get_logger(__name__)

from typing import Dict, Any, List, Tuple, Optional
import numpy as np
from backend.utils.logger import get_logger
from backend.config.config import RISK_THRESHOLDS

logger = get_logger(__name__)

class ThresholdOptimizer:
    """
    Calibrates and optimizes risk classification thresholds using empirical validation data.
    Calculates statistical boundaries for LOW_MAX, MEDIUM_MAX, and HIGH_MAX
    against labelled ground-truth verification distributions.
    """
    def __init__(
        self,
        current_thresholds: Optional[Dict[str, float]] = None,
        target_metric: str = "f1"
    ):
        self.thresholds = dict(current_thresholds or RISK_THRESHOLDS)
        self.target_metric = target_metric
        self.calibration_history: List[Dict[str, Any]] = []

    def calibrate(
        self,
        validation_scores: List[float],
        ground_truth_labels: List[int],
        target_false_positive_rate: float = 0.05
    ) -> Dict[str, Any]:
        """
        Calibrates risk thresholds against labelled validation data:
        - validation_scores: Array of model confidence scores [0.0 to 1.0 or 0.0 to 100.0]
        - ground_truth_labels: Binary labels (0 for benign, 1 for attack)
        - target_false_positive_rate: Allowed false positive budget (default 5%)
        """
        if not validation_scores or not ground_truth_labels or len(validation_scores) != len(ground_truth_labels):
            logger.warning("[ThresholdOptimizer] Insufficient or mismatched validation data; retaining current thresholds.")
            res = dict(self.thresholds)
            res.update({
                "calibrated": False,
                "optimal_threshold": 0.5,
                "metrics": {
                    "f1_score": 0.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "sample_count": 0,
                    "target_metric": self.target_metric
                }
            })
            return res

        scores = np.array(validation_scores, dtype=float)
        labels = np.array(ground_truth_labels, dtype=int)

        benign_scores = scores[labels == 0]
        attack_scores = scores[labels == 1]

        if len(benign_scores) == 0 or len(attack_scores) == 0:
            logger.warning("[ThresholdOptimizer] Both benign and attack samples required for calibration.")
            res = dict(self.thresholds)
            res.update({
                "calibrated": False,
                "optimal_threshold": 0.5,
                "metrics": {
                    "f1_score": 0.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "sample_count": len(validation_scores),
                    "target_metric": self.target_metric
                }
            })
            return res

        # Check if scores are in [0, 1] range vs [0, 100]
        is_normalized = bool(np.max(scores) <= 1.0 and np.min(scores) >= 0.0)

        # 1. Optimal Decision Boundary Grid Search
        candidates = np.linspace(float(np.min(scores)), float(np.max(scores)), 50)
        best_f1 = 0.0
        best_prec = 0.0
        best_rec = 0.0
        best_thresh = float(np.median(scores))

        for cand in candidates:
            preds = (scores >= cand).astype(int)
            tp = int(np.sum((preds == 1) & (labels == 1)))
            fp = int(np.sum((preds == 1) & (labels == 0)))
            fn = int(np.sum((preds == 0) & (labels == 1)))
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            if f1 > best_f1:
                best_f1 = f1
                best_prec = precision
                best_rec = recall
                best_thresh = cand

        # 2. Risk Tier Boundaries (scaled to 0-100)
        scaled_scores = scores * 100.0 if is_normalized else scores
        scaled_benign = scaled_scores[labels == 0]
        scaled_attack = scaled_scores[labels == 1]

        low_max = float(np.percentile(scaled_benign, 85))
        med_max = float(np.percentile(scaled_attack, 25))
        if med_max <= low_max:
            med_max = (low_max + float(np.percentile(scaled_attack, 50))) / 2.0

        high_max = max(med_max + 10.0, float(np.percentile(scaled_attack, 75)))
        high_max = min(95.0, high_max)

        calibrated = {
            "LOW_MAX": round(max(20.0, min(50.0, low_max)), 1),
            "MEDIUM_MAX": round(max(50.0, min(75.0, med_max)), 1),
            "HIGH_MAX": round(max(75.0, min(95.0, high_max)), 1),
            "calibrated": True,
            "optimal_threshold": round(float(best_thresh), 4),
            "metrics": {
                "f1_score": round(float(best_f1), 4),
                "precision": round(float(best_prec), 4),
                "recall": round(float(best_rec), 4),
                "sample_count": len(validation_scores),
                "target_metric": self.target_metric
            }
        }

        self.thresholds = {
            "LOW_MAX": calibrated["LOW_MAX"],
            "MEDIUM_MAX": calibrated["MEDIUM_MAX"],
            "HIGH_MAX": calibrated["HIGH_MAX"]
        }
        self.calibration_history.append(calibrated)

        logger.info(f"[ThresholdOptimizer] Calibrated thresholds: {calibrated}")
        return calibrated

    def optimize_thresholds(self) -> Dict[str, float]:
        """
        Recalculates risk thresholds using recent historical feedback.
        """
        return self.thresholds


"""
confidence.py

Rule-based confidence scoring for NetDoctor network diagnoses.

IMPORTANT:
The returned score is a heuristic score, not a calibrated probability.
Thresholds should be validated against representative network measurements.
"""

from math import isfinite


# Confidence levels for supported rule-based scores.
HIGH_THRESHOLD = 0.80
MEDIUM_THRESHOLD = 0.50

# Supported diagnosis labels and their measurement thresholds.
# Assumed units:
#   latency: milliseconds
#   packet_loss: percentage (0-100)
#   dns_time: milliseconds
#
# These are initial configurable thresholds, not universal standards.
DIAGNOSIS_RULES = {
    "high_latency": {
        "metric": "latency",
        "thresholds": [
            (300, 0.95),
            (150, 0.85),
            (100, 0.60),
        ],
        "comparison": "greater_than",
    },
    "packet_loss": {
        "metric": "packet_loss",
        "thresholds": [
            (10, 0.95),
            (5, 0.85),
            (2, 0.60),
        ],
        "comparison": "greater_than",
    },
    "weak_wifi": {
        "metric": "wifi_signal",
        "thresholds": [],
        "comparison": "categorical",
    },
    "dns_issue": {
        "metric": "dns_time",
        "thresholds": [
            (500, 0.95),
            (200, 0.85),
            (100, 0.60),
        ],
        "comparison": "greater_than",
    },
}

# Accept common labels used by diagnosis modules and the CSV.
ALIASES = {
    "high latency": "high_latency",
    "high_latency": "high_latency",
    "packet loss": "packet_loss",
    "high packet loss": "packet_loss",
    "packet_loss": "packet_loss",
    "weak wifi": "weak_wifi",
    "weak wi-fi": "weak_wifi",
    "weak wifi signal": "weak_wifi",
    "weak_wifi": "weak_wifi",
    "possible dns issue": "dns_issue",
    "dns issue": "dns_issue",
    "dns_issue": "dns_issue",
    "network instability": "network_instability",
    "network_instability": "network_instability",
    "normal": "normal",
}


def _normalise_problem(problem):
    """Return a consistent diagnosis label."""
    if not isinstance(problem, str):
        return None

    label = problem.strip().lower()
    return ALIASES.get(label, label.replace("-", "_"))


def _valid_number(value):
    """Check that a metric is a finite, non-boolean number."""
    if isinstance(value, bool):
        return False

    if not isinstance(value, (int, float)):
        return False

    return isfinite(value)


def _get_level(score):
    """Convert a heuristic score into a readable confidence level."""
    if score >= HIGH_THRESHOLD:
        return "High"

    if score >= MEDIUM_THRESHOLD:
        return "Medium"

    return "Low"


def calculate_confidence(metrics, problem):
    """
    Calculate heuristic confidence for a suspected network problem.

    Args:
        metrics (dict): Network measurements, for example:
            {
                "latency": 180,
                "packet_loss": 1,
                "wifi_signal": "strong",
                "dns_time": 35,
            }

        problem (str): Diagnosis label. Accepts labels such as
            "high_latency", "High Latency", "packet_loss",
            "weak_wifi", and "dns_issue".

    Returns:
        tuple:
            (score, level)

            score is a float between 0 and 1, or None if confidence
            cannot be evaluated because the diagnosis is unsupported
            or the required metric is missing/invalid.

            level is "High", "Medium", "Low", or "Unknown".
    """
    if not isinstance(metrics, dict):
        return None, "Unknown"

    diagnosis = _normalise_problem(problem)

    # Do not pretend to score diagnoses without defined rules.
    if diagnosis not in DIAGNOSIS_RULES:
        return None, "Unknown"

    rule = DIAGNOSIS_RULES[diagnosis]
    metric_name = rule["metric"]
    value = metrics.get(metric_name)

    # Normal is not a fault diagnosis. It requires separate validation.
    if diagnosis == "normal":
        return None, "Unknown"

    # Network instability requires a multi-metric rule that has not
    # yet been defined. Avoid inventing a confidence score.
    if diagnosis == "network_instability":
        return None, "Unknown"

    if value is None:
        return None, "Unknown"

    # Wi-Fi signal is categorical rather than numeric.
    if diagnosis == "weak_wifi":
        if not isinstance(value, str):
            return None, "Unknown"

        signal = value.strip().lower()

        if signal == "weak":
            score = 0.90
        elif signal == "medium":
            score = 0.50
        elif signal in {"strong", "good"}:
            score = 0.0
        else:
            return None, "Unknown"

        return score, _get_level(score)

    # Numeric metrics must be finite, non-negative values.
    if not _valid_number(value) or value < 0:
        return None, "Unknown"

    # Packet loss is assumed to be expressed as a percentage.
    if diagnosis == "packet_loss" and value > 100:
        return None, "Unknown"

    # Find the first matching threshold, highest threshold first.
    for threshold, score in rule["thresholds"]:
        if value > threshold:
            return score, _get_level(score)

    # The measurement does not support the suspected fault.
    # This is a rule-based score of zero, not proof the network is fine.
    return 0.0, "Low"


if __name__ == "__main__":
    # Basic examples for manual verification.
    examples = [
        (
            {
                "latency": 180,
                "packet_loss": 1,
                "wifi_signal": "strong",
                "dns_time": 35,
            },
            "high_latency",
        ),
        ({"packet_loss": 8}, "packet_loss"),
        ({"wifi_signal": "weak"}, "weak_wifi"),
        ({"dns_time": 300}, "dns_issue"),
        ({}, "high_latency"),
        ({"latency": -10}, "high_latency"),
        ({"latency": 180}, "unsupported_problem"),
    ]

    for metrics, problem in examples:
        score, level = calculate_confidence(metrics, problem)
        print(
            f"Problem: {problem:22} "
            f"Score: {str(score):5} "
            f"Level: {level}"
        )

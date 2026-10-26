"""Detection configuration: defaults, loading, saving and validation.

Thresholds live in a JSON file (``instance/rules.json`` by default) so they
can be tuned from the Rules page or by hand without touching code. Missing
keys fall back to the defaults declared on each rule.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from pathlib import Path

from ..db import SEVERITIES
from .base import Param
from .rules import ALL_RULES, RULES_BY_ID

GLOBAL_PARAMS = (
    Param("allowlist_ips", "str_list", ["127.0.0.1", "::1"], "Allow-listed IPs / networks",
          "Events from these IPs or CIDR ranges (one per line) are ignored by every rule. "
          "Use it for your own scanners, monitoring and load balancers."),
)


def default_config() -> dict:
    return {
        "global": {p.name: copy.deepcopy(p.default) for p in GLOBAL_PARAMS},
        "rules": {rule.id: copy.deepcopy(rule.defaults()) for rule in ALL_RULES},
    }


def _merge(defaults: dict, overrides: dict) -> dict:
    merged = copy.deepcopy(defaults)
    for key, value in (overrides or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict) and key != "patterns":
            merged[key] = _merge(merged[key], value)
        elif key in merged:
            merged[key] = value
    return merged


def load_config(path: str | Path | None) -> dict:
    """Defaults overlaid with the JSON file (if it exists and is valid)."""
    config = default_config()
    if path and Path(path).exists():
        try:
            overrides = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return config
        config = _merge(config, overrides)
    return config


def save_config(path: str | Path, config: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(config, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------
# Validation (used by the Rules page form)
# --------------------------------------------------------------------------
def _lines(text) -> list[str]:
    if isinstance(text, (list, tuple)):
        return [str(t).strip() for t in text if str(t).strip()]
    return [line.strip() for line in str(text or "").splitlines() if line.strip()]


def coerce_param(param: Param, raw):
    """Convert a raw form value into the parameter's type or raise ValueError."""
    kind = param.kind
    if kind == "bool":
        return raw in (True, "on", "true", "1", 1, "yes")
    if kind in ("int", "float"):
        try:
            value = int(raw) if kind == "int" else float(raw)
        except (TypeError, ValueError):
            raise ValueError(f"{param.label}: must be a number") from None
        if param.minimum is not None and value < param.minimum:
            raise ValueError(f"{param.label}: must be at least {param.minimum:g}")
        if param.maximum is not None and value > param.maximum:
            raise ValueError(f"{param.label}: must be at most {param.maximum:g}")
        return value
    if kind == "severity":
        if raw not in SEVERITIES:
            raise ValueError(f"{param.label}: choose one of {', '.join(SEVERITIES)}")
        return raw
    if kind == "choice":
        if raw not in param.choices:
            raise ValueError(f"{param.label}: choose one of {', '.join(param.choices)}")
        return raw
    if kind == "str_list":
        return _lines(raw)
    if kind == "int_list":
        try:
            values = [int(v) for v in _lines(raw)]
        except ValueError:
            raise ValueError(f"{param.label}: one whole number per line") from None
        if not values:
            raise ValueError(f"{param.label}: enter at least one value")
        return values
    if kind == "pattern_map":
        mapping = {}
        if isinstance(raw, dict):
            items = raw.items()
        else:
            items = []
            for line in _lines(raw):
                if "=" not in line:
                    raise ValueError(f"{param.label}: '{line}' must look like 'pattern = severity'")
                pattern, severity = line.rsplit("=", 1)
                items.append((pattern, severity))
        for pattern, severity in items:
            pattern, severity = str(pattern).strip(), str(severity).strip().lower()
            if severity not in SEVERITIES:
                raise ValueError(f"{param.label}: unknown severity '{severity}' for '{pattern}'")
            if pattern:
                mapping[pattern] = severity
        return mapping
    raise ValueError(f"unknown parameter type {kind}")


def validate_allowlist(entries: list[str]) -> list[str]:
    for entry in entries:
        try:
            ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ValueError(f"Allow-list: '{entry}' is not an IP address or CIDR range") from None
    return entries


def config_from_form(form) -> tuple[dict, list[str]]:
    """Build a config from submitted form fields named '<rule_id>__<param>'.

    Returns (config, errors). Booleans missing from the form are False
    (unchecked checkboxes are not submitted).
    """
    config, errors = default_config(), []
    for param in GLOBAL_PARAMS:
        try:
            value = coerce_param(param, form.get(f"global__{param.name}", ""))
            config["global"][param.name] = validate_allowlist(value) if param.name == "allowlist_ips" else value
        except ValueError as exc:
            errors.append(str(exc))
    for rule in ALL_RULES:
        for param in rule.all_params():
            field = f"{rule.id}__{param.name}"
            raw = form.get(field, False if param.kind == "bool" else None)
            if raw is None:
                continue  # keep default
            try:
                config["rules"][rule.id][param.name] = coerce_param(param, raw)
            except ValueError as exc:
                errors.append(f"{rule.name} - {exc}")
    return config, errors


def form_value(param: Param, value) -> str:
    """Render a config value for an HTML input/textarea."""
    if param.kind in ("str_list", "int_list"):
        return "\n".join(str(v) for v in value)
    if param.kind == "pattern_map":
        return "\n".join(f"{k} = {v}" for k, v in value.items())
    return "" if value is None else str(value)


def get_rule(rule_id: str):
    return RULES_BY_ID[rule_id]

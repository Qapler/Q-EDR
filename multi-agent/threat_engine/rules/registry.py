"""
Rule registry: auto-discovers and manages all threat detection rules.

Rules are discovered by importing each rule module and inspecting it for
concrete `Rule` subclasses.  The registry exposes query helpers used by the
detection engine to retrieve rules by category, severity, or ID.
"""

import importlib
import inspect
import logging
from typing import Dict, List, Optional, Type

from .base import Rule, RuleCategory, Severity

logger = logging.getLogger(__name__)

# Ordered list of rule modules to import.  Add new modules here.
RULE_MODULES: List[str] = [
    "threat_engine.rules.lateral_movement",
    "threat_engine.rules.privilege_escalation",
    "threat_engine.rules.persistence",
    "threat_engine.rules.credential_access",
    "threat_engine.rules.defense_evasion",
    "threat_engine.rules.discovery",
    "threat_engine.rules.exfiltration",
    "threat_engine.rules.execution",
    "threat_engine.rules.command_control",
    "threat_engine.rules.impact",
]


class RuleRegistry:
    """
    Auto-discovers and manages all threat detection rules.

    On construction, every module listed in `RULE_MODULES` is imported and
    inspected.  Concrete `Rule` subclasses (those that have a non-empty
    `rule_id` and no abstract methods) are instantiated and stored in an
    internal dictionary keyed by `rule_id`.

    Duplicate `rule_id` values raise a `ValueError` at load time to prevent
    silent shadowing of rules.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, Rule] = {}
        self._failed_modules: List[str] = []
        self._load_all()

    # ------------------------------------------------------------------ #
    # Private loading logic                                                #
    # ------------------------------------------------------------------ #

    def _load_all(self) -> None:
        """Import all rule modules and register concrete Rule subclasses."""
        for module_path in RULE_MODULES:
            self._load_module(module_path)

        logger.info(
            "RuleRegistry ready",
            extra={
                "total_rules": len(self._rules),
                "enabled_rules": sum(1 for r in self._rules.values() if r.enabled),
                "failed_modules": self._failed_modules,
            },
        )

    def _load_module(self, module_path: str) -> None:
        """Import a single module and register all valid rules found in it."""
        try:
            mod = importlib.import_module(module_path)
        except Exception as exc:
            logger.error(
                "Failed to import rule module",
                extra={"module_name": module_path, "error": str(exc)},
                exc_info=True,
            )
            self._failed_modules.append(module_path)
            return

        registered = 0
        for _name, cls in inspect.getmembers(mod, inspect.isclass):
            if not issubclass(cls, Rule) or cls is Rule:
                continue
            if inspect.isabstract(cls):
                continue
            if not cls.rule_id:
                logger.warning(
                    "Skipping Rule subclass with empty rule_id",
                    extra={"class_name": cls.__qualname__, "module_name": module_path},
                )
                continue
            if cls.rule_id in self._rules:
                existing = type(self._rules[cls.rule_id]).__qualname__
                raise ValueError(
                    f"Duplicate rule_id '{cls.rule_id}': "
                    f"'{cls.__qualname__}' conflicts with '{existing}'"
                )
            try:
                instance = cls()
                self._rules[instance.rule_id] = instance
                registered += 1
                logger.debug(
                    "Registered rule",
                    extra={
                        "rule_id": instance.rule_id,
                        "severity": instance.severity.value,
                        "category": instance.category.value,
                    },
                )
            except Exception as exc:
                logger.error(
                    "Failed to instantiate rule",
                    extra={"class_name": cls.__qualname__, "error": str(exc)},
                    exc_info=True,
                )

        logger.debug(
            "Module loaded",
            extra={"module_name": module_path, "rules_registered": registered},
        )

    # ------------------------------------------------------------------ #
    # Public query interface                                               #
    # ------------------------------------------------------------------ #

    def get_all(self) -> List[Rule]:
        """Return all registered rules, enabled and disabled."""
        return list(self._rules.values())

    def get_enabled(self) -> List[Rule]:
        """Return all enabled rules."""
        return [r for r in self._rules.values() if r.enabled]

    def get_by_id(self, rule_id: str) -> Optional[Rule]:
        """Return a rule by its unique ID, or None if not found."""
        return self._rules.get(rule_id)

    def get_by_category(self, category: RuleCategory) -> List[Rule]:
        """Return all enabled rules matching the given tactic category."""
        return [
            r for r in self._rules.values()
            if r.category == category and r.enabled
        ]

    def get_by_severity(self, severity: Severity) -> List[Rule]:
        """Return all enabled rules at the given severity level."""
        return [
            r for r in self._rules.values()
            if r.severity == severity and r.enabled
        ]

    def get_by_tag(self, tag: str) -> List[Rule]:
        """Return all enabled rules that carry the given tag."""
        return [
            r for r in self._rules.values()
            if tag in (r.tags or []) and r.enabled
        ]

    # ------------------------------------------------------------------ #
    # Enable / disable                                                     #
    # ------------------------------------------------------------------ #

    def register(self, rule: Rule) -> None:
        """Register an instantiated Rule object."""
        if not rule.rule_id:
            raise ValueError("Cannot register rule with empty rule_id")
        if rule.rule_id in self._rules:
            raise ValueError(f"Duplicate rule_id '{rule.rule_id}'")
        self._rules[rule.rule_id] = rule
        logger.debug("Registered rule", extra={"rule_id": rule.rule_id})

    def enable(self, rule_id: str) -> bool:
        """Enable a rule by ID.  Returns True if the rule exists."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = True
            logger.info("Rule enabled", extra={"rule_id": rule_id})
            return True
        logger.warning("enable() called for unknown rule_id", extra={"rule_id": rule_id})
        return False

    def disable(self, rule_id: str) -> bool:
        """Disable a rule by ID.  Returns True if the rule exists."""
        if rule_id in self._rules:
            self._rules[rule_id].enabled = False
            logger.info("Rule disabled", extra={"rule_id": rule_id})
            return True
        logger.warning("disable() called for unknown rule_id", extra={"rule_id": rule_id})
        return False

    # ------------------------------------------------------------------ #
    # Introspection                                                        #
    # ------------------------------------------------------------------ #

    def summary(self) -> Dict:
        """Return a summary dict suitable for health-check endpoints."""
        total = len(self._rules)
        enabled = sum(1 for r in self._rules.values() if r.enabled)
        by_category: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for r in self._rules.values():
            cat = r.category.value
            sev = r.severity.value
            by_category[cat] = by_category.get(cat, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {
            "total": total,
            "enabled": enabled,
            "disabled": total - enabled,
            "failed_modules": self._failed_modules,
            "by_category": by_category,
            "by_severity": by_severity,
        }

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules

    def __repr__(self) -> str:
        return (
            f"<RuleRegistry total={len(self._rules)} "
            f"enabled={sum(1 for r in self._rules.values() if r.enabled)}>"
        )

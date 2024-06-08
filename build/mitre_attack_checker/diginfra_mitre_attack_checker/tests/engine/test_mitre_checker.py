from pathlib import Path
from typing import List

from diginfra_mitre_attack_checker.engine.mitre_checker import DiginfraMitreChecker
from diginfra_mitre_attack_checker.models.diginfra_mitre_errors import ErrorReason, DiginfraRulesErrors, DiginfraMitreError
from diginfra_mitre_attack_checker.tests.test_common import MITRE_DOMAIN, MITRE_VERSION, DIGINFRA_RULES_FILE

# global
mitre_checker = DiginfraMitreChecker(MITRE_DOMAIN, MITRE_VERSION)
assert mitre_checker.mitre_parser

errors: List[DiginfraMitreError] = mitre_checker.validate(DIGINFRA_RULES_FILE)
assert errors


def get_errors_by_rule(rule_name: str,
                       myerrors: "List[DiginfraMitreError]") -> "List[DiginfraMitreError]":
    return [e for e in myerrors if e.rule == rule_name]


def get_error_by_technique(technique: str,
                           myerrors: "List[DiginfraMitreError]") -> "DiginfraMitreError":
    return [e for e in myerrors if e.techniques_tags == [technique]][0]


def test_validate():
    # mitre tag not matching the technique phase
    errors_1 = get_errors_by_rule('wrong mitre rule', errors)
    assert errors_1
    assert len(errors_1) == 1
    error_1: DiginfraMitreError = get_error_by_technique('T1610', errors_1)
    assert error_1
    assert error_1.tactics_tags == ['mitre_lateral_movement']
    assert error_1.mitre_tactics_names == ['defense-evasion', 'execution']
    assert error_1.reasons == [ErrorReason.MISSING]

    # missing mitre tag for multiple techniques
    # desc: one tactic tag is missing to fulfill all the mitre phases from the tagged techniques
    errors_2 = get_errors_by_rule("wrong mitre rule multiple techniques and missing one tactic", errors)
    assert len(errors_2) == 1
    error_1020: DiginfraMitreError = get_error_by_technique('T1020', errors_2)
    assert error_1020
    assert error_1020.tactics_tags == ['mitre_credential_access', 'mitre_discovery']
    assert error_1020.mitre_tactics_names == ['exfiltration']
    assert error_1020.reasons == [ErrorReason.MISSING]

    # too many tactics tags
    errors_3 = get_errors_by_rule("too many tactics tags with multiple techniques", errors)
    assert len(errors_3) == 1
    error_tactics: DiginfraMitreError = errors_3[0]
    assert error_tactics.tactics_tags.sort() == ["mitre_discovery", "mitre_exfiltration",
                                                 "mitre_credential_access", "mitre_execution"].sort()
    assert error_tactics.mitre_tactics_names.sort() == ["mitre_discovery", "mitre_exfiltration",
                                                        "mitre_credential_access"].sort()
    assert error_tactics.reasons == [ErrorReason.OVERDO]


def test_dump():
    output = Path('/tmp/test_diginfra_mitre_checker_dump.json')
    mitre_checker.dump_errors(errors, output)
    assert output.exists()
    from_file = DiginfraRulesErrors.parse_file(output)
    assert from_file

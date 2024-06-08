import pytest

from diginfra_mitre_attack_checker.exceptions.rules_exceptions import DiginfraRulesFileContentError
from diginfra_mitre_attack_checker.parsers.diginfra_rules import DiginfraRulesParser
from diginfra_mitre_attack_checker.tests.test_common import NOT_DIGINFRA_RULES_FILE, DIGINFRA_RULES_FILE

# test diginfra rules file validation
with pytest.raises(DiginfraRulesFileContentError):
    DiginfraRulesParser(NOT_DIGINFRA_RULES_FILE)

diginfra_rules_parser = DiginfraRulesParser(DIGINFRA_RULES_FILE)
assert diginfra_rules_parser.rules


def test_get_mitre_relations():
    relations = diginfra_rules_parser.get_mitre_relations()
    assert relations
    assert len(relations) == 6

    correct_mitre_rule = relations.rules['correct mitre rule']
    assert correct_mitre_rule.tactics == ['mitre_persistence']
    assert correct_mitre_rule.techniques == ['T1098']

    wrong_mitre_rule = relations.rules['wrong mitre rule']
    assert wrong_mitre_rule.tactics == ['mitre_lateral_movement']
    assert wrong_mitre_rule.techniques == ['T1610']

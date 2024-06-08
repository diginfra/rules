import logging
from pathlib import Path
from typing import List

from diginfra_mitre_attack_checker.models.diginfra_mitre_errors import \
    ErrorReason, DiginfraMitreError, DiginfraRulesErrors
from diginfra_mitre_attack_checker.models.diginfra_mitre_relations import MitreRelations
from diginfra_mitre_attack_checker.parsers.diginfra_rules import DiginfraRulesParser
from diginfra_mitre_attack_checker.parsers.mitre_stix import MitreParser
from diginfra_mitre_attack_checker.utils.file import write_file
from diginfra_mitre_attack_checker.utils.logger import MitreCheckerLogger

logger = logging.getLogger(MitreCheckerLogger.name)


class DiginfraMitreChecker(object):

    def __init__(self, mitre_domain: str, mitre_domain_version: str):
        logger.info(f"Load Mitre ATT&CK STIX Data for domain '{mitre_domain}' and version "
                    f"'{mitre_domain_version}'")
        self.mitre_parser = MitreParser(mitre_domain, mitre_domain_version)

    def validate(self, diginfra_rules_file: Path) -> "List[DiginfraMitreError]":
        """
        This function validates the diginfra rules' extra tags against Mitre ATT&CK STIX Data when they
        contain mitre information.
        This method gets the mitre techniques or sub-techniques IDs and the mitre tactics (mitre phases)
        names in the extra tags of each diginfra rules.
        If the mitre techniques or sub-techniques IDs in the tags are not related to proper the mitre
        tactics names by comparing them with the mitre data (STIX data from Mitre CTI), this method
        considers that the rule contains an error.
        For example, if the extra tags contain :
        {"tags": ["T1611", "mitre_initial_access"] }
        And the actual mitre domain is 'enterprise-attack' in version '13.1', the tags' rule will be
        considered erroneous since the proper mitre phase for 'T1611' is 'privilege-escalation' in this
        version.
        :param diginfra_rules_file: A diginfra rule file to analyse against the Mitre ATT&CK STIX Data
        :return: A list of models containing a description of each error in the diginfra rules for Mitre
                    ATT&CK
        """
        logger.info(f"Audit Diginfra rules file '{diginfra_rules_file}' for Mitre ATT&CK")
        diginfra_rules_parser = DiginfraRulesParser(diginfra_rules_file)
        diginfra_mitre_errors: List[DiginfraMitreError] = []
        # build the model relation between technique (or sub-technique) ID and the mitre phase configured
        # in each rule
        rules_mitre_relations: MitreRelations = diginfra_rules_parser.get_mitre_relations()
        for rule_name, rule_mitre_relation in rules_mitre_relations.rules.items():
            rule_tactics = rule_mitre_relation.tactics
            all_mitre_tactics = []
            all_mitre_techniques_names = []
            all_mitre_techniques_urls = []

            # verify each technique tag against mitre data
            for rule_technique_or_tactic in rule_mitre_relation.techniques:
                mitre_technique_or_tactic = self.mitre_parser.get_tactic_or_technique_by_id(
                    rule_technique_or_tactic)
                mitre_tactics_names = self.mitre_parser.get_tactics_names(mitre_technique_or_tactic)
                formatted_mitre_tactics_names = [f"mitre_{tactic.replace('-', '_')}" for tactic in
                                                 mitre_tactics_names]
                # gather all correct mitre tactics & techniques of this rule
                all_mitre_tactics += mitre_tactics_names
                mitre_technique_name = self.mitre_parser.get_mitre_name(mitre_technique_or_tactic)
                mitre_technique_url = self.mitre_parser.get_technique_external_reference(
                    mitre_technique_or_tactic)['url']
                all_mitre_techniques_names.append(mitre_technique_name)
                all_mitre_techniques_urls.append(mitre_technique_url)
                if not set(formatted_mitre_tactics_names).issubset(set(rule_tactics)):
                    # detect errors
                    # missing tactic tag in rule for this technique
                    diginfra_error = DiginfraMitreError(rule=rule_name,
                                                  techniques_tags=[rule_technique_or_tactic],
                                                  tactics_tags=rule_tactics,
                                                  mitre_techniques_names=[mitre_technique_name],
                                                  mitre_tactics_names=mitre_tactics_names,
                                                  mitre_techniques_urls=[mitre_technique_url],
                                                  reasons=[ErrorReason.MISSING])

                    diginfra_mitre_errors.append(diginfra_error)

            # verify tactics
            all_mitre_tactics_set = set(all_mitre_tactics)
            if len(rule_tactics) > len(all_mitre_tactics_set):
                # detect errors when too many tactic tags are included into the rule extra tags
                diginfra_error = DiginfraMitreError(rule=rule_name,
                                              techniques_tags=rule_mitre_relation.techniques,
                                              tactics_tags=rule_tactics,
                                              mitre_techniques_names=list(
                                                  set(all_mitre_techniques_names)),
                                              mitre_tactics_names=list(set(all_mitre_tactics_set)),
                                              mitre_techniques_urls=list(set(all_mitre_techniques_urls)),
                                              reasons=[ErrorReason.OVERDO])
                diginfra_mitre_errors.append(diginfra_error)

        return diginfra_mitre_errors

    def autofix(self, diginfra_rules_file: Path, diginfra_mitre_errors: List[DiginfraMitreError]):
        """
        Automatically fix Mitre tags in a diginfra rules file from a provided diginfra mitre errors report
        :param diginfra_rules_file: the rules file to fix
        :param diginfra_mitre_errors: the diginfra mitre error report for this file
        """
        pass

    @staticmethod
    def dump_errors(diginfra_mitre_errors: List[DiginfraMitreError], output: Path) -> None:
        """
        Write a list of diginfra mitre errors model to a file
        :param output: output file to dump the errors
        :param diginfra_mitre_errors: List of diginfra mitre errors models
        """
        write_file(DiginfraRulesErrors(errors=diginfra_mitre_errors).json(), output)

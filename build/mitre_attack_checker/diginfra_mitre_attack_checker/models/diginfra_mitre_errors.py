from enum import Enum
from typing import List

from pydantic import BaseModel


class ErrorReason(str, Enum):
    MISSING = "One or more tactics tags are missing"
    OVERDO = "Too many tactics tags"


class DiginfraMitreError(BaseModel):
    """
    This model describe an error located in a diginfra rule and related to its mitre tag
    """
    # DIGINFRA RELATED INFORMATION
    # 'rule' is the rule description in the diginfra rules file
    rule: str
    # 'tactics_tags' are the tags of Mitre ATT&CK tactics in the current diginfra rule
    tactics_tags: List[str]
    # 'technique_tag' is the tag of a Mitre ATT&CK technique in the current diginfra rule
    techniques_tags: List[str]

    # MITRE ATT&CK RELATED INFORMATION FROM STIX DATA
    # 'mitre_tactics_names' are the Mitre ATT&CK's tactics name related to the technique tag in the
    # current diginfra rule. These names are taken from STIX data.
    mitre_tactics_names: List[str]
    # 'mitre_technique_name' is the Mitre ATT&CK's technique name related to the technique tag in the
    # current diginfra rule. This name is taken from STIX data.
    mitre_techniques_names: List[str]
    # 'mitre_technique_url' is the Mitre ATT&CK's technique url related to the technique tag in the
    # current diginfra rule. This url is taken from STIX data.
    mitre_techniques_urls: List[str]
    # details about the error
    reasons: List[ErrorReason]


class DiginfraRulesErrors(BaseModel):
    """
    This model is just useful to dump errors to disk
    """
    errors: List[DiginfraMitreError]

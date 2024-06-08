import os
from pathlib import Path

from diginfra_mitre_attack_checker.utils.logger import MitreCheckerLogger

MitreCheckerLogger()

TEST_DIR = os.path.dirname(os.path.abspath(__file__))
RESOURCES_DIR = f"{TEST_DIR}/resources"

MITRE_VERSION = "13.1"
MITRE_DOMAIN = "enterprise-attack"

DIGINFRA_RULES_FILE = Path(f"{RESOURCES_DIR}/diginfra_rules_test.yaml")
NOT_DIGINFRA_RULES_FILE = Path(f"{RESOURCES_DIR}/not_diginfra_rules_test.yaml")


def read_file(path: Path) -> "str":
    with open(path, 'r') as f:
        return str(f.read())

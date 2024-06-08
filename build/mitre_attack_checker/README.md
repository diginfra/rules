# Mitre ATT&CK Checker Module

The Mitre ATT&CK Checker module aims to check the compliance of the Diginfra rules against the Mitre ATT&CK
framework. This module provides to Diginfra experts and Diginfra users a way to check default and custom
rules for Mitre ATT&CK extra tags.
This module uses STIX from the OASIS standards. Structured Threat Information Expression (STIX™) is a
language and serialization format used to exchange cyber threat intelligence (CTI) :

- [STIX CTI documentation](https://oasis-open.github.io/cti-documentation/stix/intro)

Leveraging STIX, Mitre ATT&CK Checker fetches the ATT&CK® STIX Data from MITRE ATT&CK repositories using
the `python-stix2` library implemented by OASIS:

- [ATT&CK STIX Data repository](https://github.com/mitre-attack/attack-stix-data)
- [Python STIX2 repository](https://github.com/oasis-open/cti-python-stix2)

The choice of a module is motivated by the packaging of a python code to integrate it into wider Diginfra
implementations. More precisely, the module can be used :

- by the rules_overview_generator.py script
- by Diginfra users and experts to check their Diginfra rules files
- by other Diginfra components that need to check the validity of rules files

## Build

Requirements :

- Python >= `3.10`
- Poetry >= `1.5.1`

```sh
./build.sh
```

## Install

Requirements :

- Python >= `3.10`

```sh
./install.sh
```

Or manualy using `pip` :

```sh
pip install dist/diginfra_mitre_attack_checker-0.1.0-py3-none-any.whl
```

## Usage

```sh
python -m diginfra_mitre_attack_checker --help
```

Using the stable diginfra rules :

```sh
python -m diginfra_mitre_attack_checker -f ../../rules/diginfra_rules.yaml -o /tmp/
```

## Development

Requirements :

- Python >= `3.10`
- Poetry >= `1.5.1`

```sh
poetry check
poetry update
poetry install --sync
```

### Testing

With coverage :

```sh
poetry update
poetry run python -m pytest --cov=diginfra_mitre_attack_checker
```

```
---------- coverage: platform linux, python 3.10.12-final-0 ----------                                   
Name                                                     Stmts   Miss  Cover                             
----------------------------------------------------------------------------                             
diginfra_mitre_checker/__init__.py                              0      0   100%                             
diginfra_mitre_checker/__main__.py                              7      7     0%                             
diginfra_mitre_checker/api/__init__.py                          0      0   100%                             
diginfra_mitre_checker/api/core.py                             19     19     0%                             
diginfra_mitre_checker/cli/__init__.py                          0      0   100%                             
diginfra_mitre_checker/cli/core.py                             18     18     0%                             
diginfra_mitre_checker/engine/__init__.py                       0      0   100%                             
diginfra_mitre_checker/engine/mitre_checker.py                 46      1    98%                             
diginfra_mitre_checker/exceptions/__init__.py                   0      0   100%          
diginfra_mitre_checker/exceptions/rules_exceptions.py           8      0   100%                             
diginfra_mitre_checker/models/__init__.py                       0      0   100%                             
diginfra_mitre_checker/models/diginfra_mitre_errors.py            16      0   100%                             
diginfra_mitre_checker/models/diginfra_mitre_relations.py         14      2    86%
diginfra_mitre_checker/parsers/__init__.py                      0      0   100%
diginfra_mitre_checker/parsers/diginfra_rules.py                  30      1    97%                             
diginfra_mitre_checker/parsers/mitre_stix.py                   31      4    87%                            
diginfra_mitre_checker/tests/__init__.py                        0      0   100%                             
diginfra_mitre_checker/tests/engine/__init__.py                 0      0   100%                            
diginfra_mitre_checker/tests/engine/test_mitre_checker.py      41      0   100%                            
diginfra_mitre_checker/tests/parsers/__init__.py                0      0   100%                            
diginfra_mitre_checker/tests/parsers/test_diginfra_rules.py       18      0   100%                             
diginfra_mitre_checker/tests/parsers/test_mitre_stix.py        34      0   100%
diginfra_mitre_checker/tests/test_common.py                    13      2    85%
diginfra_mitre_checker/utils/__init__.py                        0      0   100%
diginfra_mitre_checker/utils/file.py                           10      0   100%
diginfra_mitre_checker/utils/logger.py                         36      7    81%
----------------------------------------------------------------------------
TOTAL                                                      341     61    82%
```

### Security

You should run a vulnerability scanner every time you add a new dependency in projects :

```sh
poetry update
poetry run python -m safety check
```

```
  Using non-commercial database
  Found and scanned 33 packages
  Timestamp 2023-10-02 13:43:51
  0 vulnerabilities found
  0 vulnerabilities ignored
+=======================================================================================================+

 No known security vulnerabilities found. 

+=======================================================================================================+
```



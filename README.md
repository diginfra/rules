# Diginfra Rules

[![Latest release](https://img.shields.io/github/v/release/diginfra/rules?label=Latest%20Rules%20Release&style=for-the-badge)](https://github.com/diginfra/rules/releases/latest) [![Compatible Diginfra release](https://img.shields.io/github/v/release/diginfra/diginfra?label=Compatible%20Diginfra%20Release&style=for-the-badge)](https://github.com/diginfra/diginfra/releases/latest) 

[![Docs](https://img.shields.io/badge/docs-latest-green.svg?style=for-the-badge)](https://diginfra.org/docs/rules)  [![Rules Overview](https://img.shields.io/badge/docs-latest-green.svg?label=Rules%20Overview&style=for-the-badge)](https://diginfra.github.io/rules/) [![Style Guide](https://img.shields.io/badge/docs-latest-green.svg?label=Style%20Guide&style=for-the-badge)](https://diginfra.org/docs/rules/style-guide/) 

[![Supported Fields](https://img.shields.io/badge/docs-latest-green.svg?label=Supported%20Fields&style=for-the-badge)](https://diginfra.org/docs/reference/rules/supported-fields/) [![Supported EVT ARG Fields](https://img.shields.io/badge/docs-latest-green.svg?label=Supported%20Evt%20Arg%20Fields&style=for-the-badge)](https://github.com/diginfra/libs/blob/master/driver/event_table.c)

[![Diginfra Core Repository](https://github.com/diginfra/evolution/blob/main/repos/badges/diginfra-core-blue.svg)](https://github.com/diginfra/evolution/blob/main/REPOSITORIES.md#core-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/diginfra/evolution/blob/main/REPOSITORIES.md#stable) [![License](https://img.shields.io/github/license/diginfra/rules?style=for-the-badge)](./LICENSE) [![Github Pages](https://github.com/diginfra/rules/actions/workflows/pages.yaml/badge.svg)](https://diginfra.github.io/rules/)

This repository has been created upon this [Proposal](https://github.com/diginfra/diginfra/blob/master/proposals/20221129-artifacts-distribution.md#move-diginfra-rules-to-their-own-repo) and contains the officially managed [Diginfra Rules](#diginfra-rules) by The Diginfra Project, along with the [Diginfra Rules Files Registry](#diginfra-rules-files-registry).

## Diginfra Rules

Rules tell [Diginfra](https://github.com/diginfra/diginfra) what to do. These rules are pre-defined detections for various security threats, abnormal behaviors, and compliance-related monitoring.

</br>

<p align="left">
    <img src="docs/images/start.png" alt="Image" width="21" height="21">&nbsp;&nbsp;
    Explore the <a href="https://diginfra.org/docs/rules">Official Documentation</a> for a starting point and better understanding of rule concepts. Users can modify the community-contributed Diginfra rules to fit their needs or use them as examples. In most cases, users also create their own custom rules. Keep in mind that the rules in this repository are related to Diginfra's primary monitoring functions, specifically for syscalls and container events. Meanwhile, Diginfra plugin rules are stored within the respective subfolders of the <a href="https://github.com/diginfra/plugins">Plugins</a> repository.</p>
</div>

<p align="left">
    <img src="docs/images/insight.png" alt="Image" width="18" height="24">&nbsp;&nbsp;
    Because Diginfra rules, especially Sandbox and Incubating rules, are dynamic, it's crucial to stay updated. As threats and systems evolve, Diginfra evolves with each release. Therefore, regularly check the <a href="https://diginfra.github.io/rules/">Rules Overview Document</a>, Diginfra's <a href="https://diginfra.org/docs/reference/rules/supported-fields/">Supported Fields</a>, and Diginfra's release notes with every new release. It is recommended to consistently use the most recent <a href='https://github.com/diginfra/diginfra/releases/latest'>Diginfra Release</a> to avoid compatibility issues.</p>
</div>

<p align="left">
    <img src="docs/images/setting.png" alt="Image" width="23" height="23">&nbsp;&nbsp;
    Important: The Diginfra Project only guarantees that the most recent rules releases are compatible with the latest Diginfra release. Discover all rule files in the <a href="rules/">rules/</a> folder. Refer to our <a href="./RELEASE.md">Release Process</a> and <a href="CONTRIBUTING.md#rules-maturity-framework">Rules Maturity Framework</a> for rule categorization, release procedures, and usage guidelines. Published upon tagging a new release, the <i>maturity_stable</i> rules in the <a href="rules/diginfra_rules.yaml">diginfra_rules.yaml</a> file are included in the Diginfra release package. Other maturity-level rules are released separately, requiring explicit installation and possible customization for effective <a href="CONTRIBUTING.md#justification-of-rules-maturity-framework-for-diginfra-adoption">Adoption</a>.</p>
</div>

<p align="left">
    <img src="docs/images/announce.png" alt="Image" width="20" height="20">&nbsp;&nbsp;
    Beginning with rules version 3.0.0, the <i>required_engine_version</i> follows <a href="https://semver.org/">Semantic Versioning</a> and requires Diginfra version 0.37.0 or higher. Since rules version <a href="#diginfra-rules-2x">2.0.0</a>, we've modified our rules' shipping and distribution process. With Diginfra >= 0.37.0, <a href="https://diginfra.org/docs/rules/overriding/">Selective Rules Overrides</a> aim to further streamline the customization of rules. Since Diginfra 0.36.0, you can use the <a href="https://github.com/diginfra/diginfra/blob/master/diginfra.yaml">rule_matching</a> config to resolve issues with rules overlapping, which is caused by the default "first match wins" principle. Starting from Diginfra 0.35.0, you have precise control over the syscalls that are being monitored, see <a href="https://github.com/diginfra/diginfra/blob/master/diginfra.yaml">base_syscalls</a>. Lastly, keep in mind that the <a href="CONTRIBUTING.md#rules-maturity-framework">Rules Maturity Framework</a> is a best effort on the part of the community, and ultimately, you have to decide if any rules are useful for your use cases. </p>
</div>

<p align="left">
  <img src="docs/images/cross.png" alt="Image" width="20" height="20">&nbsp;&nbsp;
  Be cautious: The <i>main</i> branch has the latest development. Before using rules from the <i>main</i> branch, check for compatibility. Changes like new output fields might cause incompatibilities with the latest stable Diginfra release. The Diginfra Project recommends using rules only from the release branches. Lastly, we'd like to highlight the importance of regular engineering effort to effectively adopt Diginfra rules. Considering that each adopter's system and monitoring needs are unique, it's advisable to view the rules as examples.
</p>

<p align="left">
  <img src="docs/images/arrow.png" alt="Image" width="20" height="20">&nbsp;&nbsp;
  Debugging: Historically, we've noted that issues often arise either from incorrect configurations or genuine bugs, acknowledging that no software is entirely bug-free. The Diginfra Project continually updates its <a href="https://diginfra.org/docs/install-operate/">Install and Operate</a> and <a href="https://diginfra.org/docs/troubleshooting/">Troubleshooting</a> guides. We kindly suggest reviewing these guides. In the context of Diginfra rules, missing fields, such as container images, may be anticipated within our imperfection tolerances under certain circumstances. We are committed to addressing and resolving issues within our control.
</p>

</br>

## Diginfra Rules Files Registry

The Diginfra Rules Files Registry contains metadata and information about rules files distributed by The Diginfra Project. The registry serves as an additional method of making the rules files available to the community, complementing the process of retrieving the rules files from this repository. 

Note: _Currently, the registry includes only rules for the syscall call data source; for other data sources see the [Plugins](https://github.com/diginfra/plugins) repository._

### Naming Convention

Rule files must be located in the [/rules](rules) folder of this repository and are named according to the following convention: `<ruleset>_rules.yaml`.

The `<ruleset>` portion represents the _ruleset_ name, which must be an alphanumeric string, separated by `-`, entirely in lowercase, and beginning with a letter.

Rule files are subsequently released using Git tags. The tag name should follow the pattern `<ruleset>-rules-<version>`, where `<version>` adheres to [Semantic Versioning](https://semver.org/). See [RELEASE](RELEASE.md) document for more details about our release process.

For instance, the _diginfra_ ruleset is stored under [/rules/diginfra_rules.yaml](rules/diginfra_rules.yaml), and its version _1.0.0_ was released using the [diginfra-rules-1.0.0](https://github.com/diginfra/rules/releases/tag/diginfra-rules-1.0.0) tag.

Note: _This convention applies to this repository only. Diginfra application does not impose any naming convention for naming rule files._

<!-- Check out the sections below to know how to [register your rules](#registering-a-new-rule) and see rules currently contained in the registry. -->

<!--
### Registering a new Rules file

Registering your rule inside the registry helps ensure that some technical constraints are respected. Moreover, this is a great way to share your ruleset and make it available to the community. We encourage you to register your ruleset in this registry before publishing it.

The registration process involves adding an entry about your rule inside the [registry.yaml](./registry.yaml) file by creating a Pull Request in this repository. Please be mindful of a few constraints that are automatically checked and required for your rule to be accepted:

- The `name` field is mandatory and must be **unique** across all the rule in the registry
- The rule `name` must match this [regular expression](https://en.wikipedia.org/wiki/Regular_expression): `^[a-z]+[a-z0-9-_\-]*$` (however, its not reccomended to use `_` in the name)
- The `path` field should specify the path to the rule in this repository
- The `url` field should point to the ruleset file in the source code

For reference, here's an example of an entry for a rule:
```yaml
- name: diginfra-rules
  description: Diginfra rules that are loaded by default
  authors: The Diginfra Authors
  contact: https://diginfra.org/community
  maintainers:
    - name: The Diginfra Authors
      email: cncf-diginfra-dev@lists.cncf.io
  path: rules/diginfra_rules.yaml
  license: apache-2.0
  url: https://github.com/diginfra/rules/blob/main/rules/diginfra_rules.yaml
```

You can find the full registry specification here: *(coming soon...)*

### Registered Rules

Please refer to the automatically generated [rules overview](https://diginfra.github.io/rules/overview/) document file for a detailed list of all the rules currently registered.

-->

## Diginfra Rules 2.x

Since version 2.0.0, the rules distributed from this repository have been split into three parts:

- [Stable](https://github.com/diginfra/rules/blob/main/rules/diginfra_rules.yaml) Diginfra rules. Those are the only ones that are bundled in the Diginfra by default. It is very important to have a set of stable rules vetted by the community. To learn more about the criterias that are required for a rule to become stable, see the [Contributing](https://github.com/diginfra/rules/blob/main/CONTRIBUTING.md) guide.
- [Incubating](https://github.com/diginfra/rules/blob/main/rules/diginfra-incubating_rules.yaml) rules, which provide a certain level of robustness guarantee but have been identified by experts as catering to more specific use cases, which may or may not be relevant for each adopter.
- [Sandbox](https://github.com/diginfra/rules/blob/main/rules/diginfra-sandbox_rules.yaml) rules, which are more experimental.

Previously, Diginfra used to bundle all the community rules in its default distribution. Today you can choose which set of rules you want to load in your distribution, depending on your preferred installation method:

### Helm Chart

If you are using the official Helm chart, you can add the incubating and/or sandbox repository in your [diginfractl](https://github.com/diginfra/charts/blob/f1062000e2e61332b3a8ea892a1765e4f4a60ec6/diginfra/values.yaml#L406) config and by enabling them in the corresponding `diginfra.yaml` file.

For instance, in order to install the Helm chart and load all the available Diginfra rules with automatic update on all of them, you can run

```
helm install diginfra diginfra/diginfra --set "diginfractl.config.artifact.install.refs={diginfra-rules:2,diginfra-incubating-rules:2,diginfra-sandbox-rules:2}" --set "diginfractl.config.artifact.follow.refs={diginfra-rules:2,diginfra-incubating-rules:2,diginfra-sandbox-rules:2}" --set "diginfra.rules_file={/etc/diginfra/k8s_audit_rules.yaml,/etc/diginfra/rules.d,/etc/diginfra/diginfra_rules.yaml,/etc/diginfra/diginfra-incubating_rules.yaml,/etc/diginfra/diginfra-sandbox_rules.yaml}"
```

Where the option `diginfractl.config.artifact.install.refs` governs which rules are downloaded at startup, `diginfractl.config.artifact.follow.refs` identifies which rules are automatically updated and `diginfra.rules_file` indicates which rules are loaded by the engine.

### Host installation

If you are managing your Diginfra installation you should be aware of which directories contain the rules. Those are governed by the `rules_file` configuration option in your [diginfra.yaml](https://github.com/diginfra/diginfra/blob/ab6d76e6d2a076ca1403c91aa62213d2cadb73ea/diginfra.yaml#L146). Normally, there is also a `rules.d` directory that you can use to upload extra rules or you can add your custom files.

Now you can simply download incubating or sandbox rules from the [rules](https://download.diginfra.org/?prefix=rules/) repository, uncompress and copy the file there.


## Contributing

If you are interested in helping and wish to contribute, we kindly request that you review our general [Contribution Guidelines](https://github.com/diginfra/.github/blob/master/CONTRIBUTING.md) and, more specifically, the dedicated [Rules Contributing](CONTRIBUTING.md) guide hosted in this repository. Please be aware that our reviewers will ensure compliance with the rules' acceptance criteria.

## License

This project is licensed to you under the [Apache 2.0 Open Source License](./LICENSE).

# host-discover public source and dependency notices

Original first-party code, documentation, synthetic fixtures and service-unit
sources included here are licensed at your option under
`BSD-3-Clause OR GPL-3.0-only`; see [LICENSE](LICENSE) and the complete texts
in [LICENSES](LICENSES/).

host-identify, host-install and box-control are separately maintained Zog
components. host-discover consumes their runtime interfaces but does not
vendor their source, privileged configuration, identity storage or live
operational evidence. Python tooling and dependencies (including setuptools,
pytest and host-identify's crypto/HTTP dependencies) retain their respective
licenses and notices. Redistribution of acquired dependencies needs a
separate artifact/license review.

Examples, test data and generated local key fixtures use non-production
identities. This public repository deliberately excludes prior private Git
commits, tags, contributor handoffs, deployed host records, grants, account
credentials and production acceptance records.

Component-development packaging does not authorize a separate PyPI upload;
public Python distribution remains the aggregate `zog` project assembled
through release-build.

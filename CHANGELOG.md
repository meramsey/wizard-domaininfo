# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

<!-- insertion marker -->
## [0.2.6](https://github.com/meramsey/wizard-domaininfo/releases/tag/0.2.6) - 2021-12-09

<small>[Compare with 0.2.5](https://github.com/meramsey/wizard-domaininfo/compare/0.2.5...0.2.6)</small>

### Bug Fixes
- ci issues ([ad2e3c4](https://github.com/meramsey/wizard-domaininfo/commit/ad2e3c47d029acb25d39d96b741d5bead4055a70) by Michael Ramsey).
- updated gitignore to add poetry.lock file ([76d6258](https://github.com/meramsey/wizard-domaininfo/commit/76d6258a3cb1dece8ecc2fa239afc9c85768ee50) by Michael Ramsey).


## [0.2.5](https://github.com/meramsey/wizard-domaininfo/releases/tag/0.2.5) - 2021-03-30

<small>[Compare with 0.2.4](https://github.com/meramsey/wizard-domaininfo/compare/0.2.4...0.2.5)</small>

### Bug Fixes
- commented out test line which was calling function unnecessarily ([4899fba](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/4899fbaf665eba2b23a50c2de9b6150b88d46f0e) by Michael Ramsey).


## [0.2.4](https://github.com/meramsey/wizard-domaininfo/releases/tag/0.2.4) - 2021-03-30

<small>[Compare with 0.2.3](https://github.com/meramsey/wizard-domaininfo/compare/0.2.3...0.2.4)</small>

### Bug Fixes
- fix asyncio event loops with new get or create new event loop function ([acc799b](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/acc799b14d0ffe7d7008077881bcfb4d46448a65) by Michael Ramsey).


## [0.2.3](https://github.com/meramsey/wizard-domaininfo/tags/0.2.3) - 2021-03-28

<small>[Compare with 0.2.2](https://github.com/meramsey/wizard-domaininfo/compare/0.2.2...0.2.3)</small>

### Bug Fixes
- fixed asyncio eventloop missing after automated fixes changed it ([531f0e1](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/531f0e12d49c233dcda1e15415012b7439f3711b) by Michael Ramsey).
- check types incompatible with legacy third party pwhois ([fb3d251](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/fb3d2517c83afdef21d9453fa2beb98858c5f6ee) by Michael Ramsey).


## [0.2.2](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.2) - 2021-03-28

<small>[Compare with 0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.1...0.2.2)</small>

### Bug Fixes
- fixed mkdocs build issue ([2b680d1](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2b680d1574fa790e3e8008d4b576b507a2c86dc8) by Michael Ramsey).
- pwhois import and console script ([c1ace5e](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/c1ace5e78c8b805bba0c368ce91a47cf5ec6ec92) by Michael Ramsey).
- updated docs to add missing references ([67e5dc6](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/67e5dc6569537f74991f84df8d5908b0743577fb) by Michael Ramsey).
- add missing references to files ([2fae1ef](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2fae1efc4970921800a03661899bfd1e5827a7fd) by Michael Ramsey).
- moved legacy test_parse.py outside tests folder to prevent issues ([84ec99c](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/84ec99cccd3938de10060a522f61c2415003fad4) by Michael Ramsey).
- added missing tests/data and refactored stuff ([7c78760](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/7c7876002a91667f765ec7dc6280545a48b7118e) by Michael Ramsey).
- fixed asyncio issue with dnslookups when threaded without existing eventloop ([f1349fd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f1349fd849805e3570f6319dbeae10d343ef0736) by Michael Ramsey).

## [0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.1) - 2021-03-28

<small>[Compare with 0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.0...0.2.1)</small>

### Bug Fixes
- fixed check-types ci failing and updated configs ([ff1a9b6](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/ff1a9b6c3d3dd32902f1bc2b0c9b1322d47e9150) by Michael Ramsey).

## [0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.0) - 2021-03-28

<small>[Compare with 0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.1...0.2.0)</small>

### Bug Fixes
- fix documentation failing ci ([4be75c2](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/4be75c2bf3d922696d97dd79993db2dd20f73c5a) by Michael Ramsey).
- change quality-template image to python:3.6 ([2d04f6b](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2d04f6b7965ae52f8b25e8e786002d6e833bdcbe) by Michael Ramsey).
- switched pages to python3.6 as pip keeps failing on python 3.8 for gitlab ([793f8fa](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/793f8fa2e687a44d5dfab96a410dabf97872d7ed) by Michael Ramsey).
- updated stuff to new general stuff to test gitlab CI for copier-poetry ([2b7ad36](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2b7ad364531283b5a633661cfbc1657354f51afa) by Michael Ramsey).
- reverted some changes so pages would properly deploy ([edf06b7](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/edf06b73b3de22dbded3b6f49fc1093db07cc1c4) by Michael Ramsey).
- added minor missing test action before coverage ([88b5939](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/88b593906eb5bfd96aa28553d2553ea589e547c5) by Michael Ramsey).
- tests and CI .gitlab-ci.yml to be more efficient ([60f46a1](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/60f46a18219c047a6b4d3d68c7eead897b79dca4) by Michael Ramsey).

### Features
- add dns lookup utils and new files ([f257827](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f257827eae87d535bbb3930b76a755c28e1a1ac9) by Michael Ramsey).

## [0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.1) - 2021-03-09

<small>[Compare with 0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.0...0.1.1)</small>

### Bug Fixes
- Updated duties.py to clean public ([5ab03dd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/5ab03dd793bc6bb1980947c08a6c4d4186fe428f) by Michael Ramsey).

## [0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.0) - 2021-03-09

<small>[Compare with first commit](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/b1b7ca3d1258efd0456dc46f62cb6cdddb45b060...0.1.0)</small>


## [0.2.2](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.2) - 2021-03-28

<small>[Compare with 0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.1...0.2.2)</small>

### Bug Fixes
- updated docs to add missing references ([67e5dc6](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/67e5dc6569537f74991f84df8d5908b0743577fb) by Michael Ramsey).
- add missing references to files ([2fae1ef](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2fae1efc4970921800a03661899bfd1e5827a7fd) by Michael Ramsey).
- moved legacy test_parse.py outside tests folder to prevent issues ([84ec99c](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/84ec99cccd3938de10060a522f61c2415003fad4) by Michael Ramsey).
- added missing tests/data and refactored stuff ([7c78760](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/7c7876002a91667f765ec7dc6280545a48b7118e) by Michael Ramsey).
- fixed asyncio issue with dnslookups when threaded without existing eventloop ([f1349fd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f1349fd849805e3570f6319dbeae10d343ef0736) by Michael Ramsey).

## [0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.1) - 2021-03-28

<small>[Compare with 0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.0...0.2.1)</small>

### Bug Fixes
- fixed check-types ci failing and updated configs ([ff1a9b6](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/ff1a9b6c3d3dd32902f1bc2b0c9b1322d47e9150) by Michael Ramsey).

## [0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.0) - 2021-03-28

<small>[Compare with 0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.1...0.2.0)</small>

### Bug Fixes
- fix documentation failing ci ([4be75c2](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/4be75c2bf3d922696d97dd79993db2dd20f73c5a) by Michael Ramsey).
- change quality-template image to python:3.6 ([2d04f6b](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2d04f6b7965ae52f8b25e8e786002d6e833bdcbe) by Michael Ramsey).
- switched pages to python3.6 as pip keeps failing on python 3.8 for gitlab ([793f8fa](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/793f8fa2e687a44d5dfab96a410dabf97872d7ed) by Michael Ramsey).
- updated stuff to new general stuff to test gitlab CI for copier-poetry ([2b7ad36](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2b7ad364531283b5a633661cfbc1657354f51afa) by Michael Ramsey).
- reverted some changes so pages would properly deploy ([edf06b7](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/edf06b73b3de22dbded3b6f49fc1093db07cc1c4) by Michael Ramsey).
- added minor missing test action before coverage ([88b5939](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/88b593906eb5bfd96aa28553d2553ea589e547c5) by Michael Ramsey).
- tests and CI .gitlab-ci.yml to be more efficient ([60f46a1](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/60f46a18219c047a6b4d3d68c7eead897b79dca4) by Michael Ramsey).

### Features
- add dns lookup utils and new files ([f257827](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f257827eae87d535bbb3930b76a755c28e1a1ac9) by Michael Ramsey).

## [0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.1) - 2021-03-09

<small>[Compare with 0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.0...0.1.1)</small>

### Bug Fixes
- Updated duties.py to clean public ([5ab03dd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/5ab03dd793bc6bb1980947c08a6c4d4186fe428f) by Michael Ramsey).

## [0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.0) - 2021-03-09

<small>[Compare with first commit](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/b1b7ca3d1258efd0456dc46f62cb6cdddb45b060...0.1.0)</small>


## [0.2.2](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.2) - 2021-03-28

<small>[Compare with 0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.1...0.2.2)</small>

### Bug Fixes
- add missing references to files ([2fae1ef](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2fae1efc4970921800a03661899bfd1e5827a7fd) by Michael Ramsey).
- moved legacy test_parse.py outside tests folder to prevent issues ([84ec99c](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/84ec99cccd3938de10060a522f61c2415003fad4) by Michael Ramsey).
- added missing tests/data and refactored stuff ([7c78760](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/7c7876002a91667f765ec7dc6280545a48b7118e) by Michael Ramsey).
- fixed asyncio issue with dnslookups when threaded without existing eventloop ([f1349fd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f1349fd849805e3570f6319dbeae10d343ef0736) by Michael Ramsey).

## [0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.1) - 2021-03-28

<small>[Compare with 0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.0...0.2.1)</small>

### Bug Fixes
- fixed check-types ci failing and updated configs ([ff1a9b6](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/ff1a9b6c3d3dd32902f1bc2b0c9b1322d47e9150) by Michael Ramsey).

## [0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.0) - 2021-03-28

<small>[Compare with 0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.1...0.2.0)</small>

### Bug Fixes
- fix documentation failing ci ([4be75c2](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/4be75c2bf3d922696d97dd79993db2dd20f73c5a) by Michael Ramsey).
- change quality-template image to python:3.6 ([2d04f6b](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2d04f6b7965ae52f8b25e8e786002d6e833bdcbe) by Michael Ramsey).
- switched pages to python3.6 as pip keeps failing on python 3.8 for gitlab ([793f8fa](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/793f8fa2e687a44d5dfab96a410dabf97872d7ed) by Michael Ramsey).
- updated stuff to new general stuff to test gitlab CI for copier-poetry ([2b7ad36](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2b7ad364531283b5a633661cfbc1657354f51afa) by Michael Ramsey).
- reverted some changes so pages would properly deploy ([edf06b7](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/edf06b73b3de22dbded3b6f49fc1093db07cc1c4) by Michael Ramsey).
- added minor missing test action before coverage ([88b5939](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/88b593906eb5bfd96aa28553d2553ea589e547c5) by Michael Ramsey).
- tests and CI .gitlab-ci.yml to be more efficient ([60f46a1](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/60f46a18219c047a6b4d3d68c7eead897b79dca4) by Michael Ramsey).

### Features
- add dns lookup utils and new files ([f257827](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f257827eae87d535bbb3930b76a755c28e1a1ac9) by Michael Ramsey).

## [0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.1) - 2021-03-09

<small>[Compare with 0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.0...0.1.1)</small>

### Bug Fixes
- Updated duties.py to clean public ([5ab03dd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/5ab03dd793bc6bb1980947c08a6c4d4186fe428f) by Michael Ramsey).

## [0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.0) - 2021-03-09

<small>[Compare with first commit](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/b1b7ca3d1258efd0456dc46f62cb6cdddb45b060...0.1.0)</small>


## [0.2.2](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.2) - 2021-03-28

<small>[Compare with 0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.1...0.2.2)</small>

### Bug Fixes
- moved legacy test_parse.py outside tests folder to prevent issues ([84ec99c](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/84ec99cccd3938de10060a522f61c2415003fad4) by Michael Ramsey).
- added missing tests/data and refactored stuff ([7c78760](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/7c7876002a91667f765ec7dc6280545a48b7118e) by Michael Ramsey).
- fixed asyncio issue with dnslookups when threaded without existing eventloop ([f1349fd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f1349fd849805e3570f6319dbeae10d343ef0736) by Michael Ramsey).

## [0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.1) - 2021-03-28

<small>[Compare with 0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.0...0.2.1)</small>

### Bug Fixes
- fixed check-types ci failing and updated configs ([ff1a9b6](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/ff1a9b6c3d3dd32902f1bc2b0c9b1322d47e9150) by Michael Ramsey).

## [0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.0) - 2021-03-28

<small>[Compare with 0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.1...0.2.0)</small>

### Bug Fixes
- fix documentation failing ci ([4be75c2](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/4be75c2bf3d922696d97dd79993db2dd20f73c5a) by Michael Ramsey).
- change quality-template image to python:3.6 ([2d04f6b](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2d04f6b7965ae52f8b25e8e786002d6e833bdcbe) by Michael Ramsey).
- switched pages to python3.6 as pip keeps failing on python 3.8 for gitlab ([793f8fa](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/793f8fa2e687a44d5dfab96a410dabf97872d7ed) by Michael Ramsey).
- updated stuff to new general stuff to test gitlab CI for copier-poetry ([2b7ad36](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2b7ad364531283b5a633661cfbc1657354f51afa) by Michael Ramsey).
- reverted some changes so pages would properly deploy ([edf06b7](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/edf06b73b3de22dbded3b6f49fc1093db07cc1c4) by Michael Ramsey).
- added minor missing test action before coverage ([88b5939](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/88b593906eb5bfd96aa28553d2553ea589e547c5) by Michael Ramsey).
- tests and CI .gitlab-ci.yml to be more efficient ([60f46a1](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/60f46a18219c047a6b4d3d68c7eead897b79dca4) by Michael Ramsey).

### Features
- add dns lookup utils and new files ([f257827](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f257827eae87d535bbb3930b76a755c28e1a1ac9) by Michael Ramsey).

## [0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.1) - 2021-03-09

<small>[Compare with 0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.0...0.1.1)</small>

### Bug Fixes
- Updated duties.py to clean public ([5ab03dd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/5ab03dd793bc6bb1980947c08a6c4d4186fe428f) by Michael Ramsey).

## [0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.0) - 2021-03-09

<small>[Compare with first commit](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/b1b7ca3d1258efd0456dc46f62cb6cdddb45b060...0.1.0)</small>


## [0.2.2](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.2) - 2021-03-28

<small>[Compare with 0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.1...0.2.2)</small>

### Bug Fixes
- added missing tests/data and refactored stuff ([7c78760](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/7c7876002a91667f765ec7dc6280545a48b7118e) by Michael Ramsey).
- fixed asyncio issue with dnslookups when threaded without existing eventloop ([f1349fd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f1349fd849805e3570f6319dbeae10d343ef0736) by Michael Ramsey).

## [0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.1) - 2021-03-28

<small>[Compare with 0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.0...0.2.1)</small>

### Bug Fixes
- fixed check-types ci failing and updated configs ([ff1a9b6](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/ff1a9b6c3d3dd32902f1bc2b0c9b1322d47e9150) by Michael Ramsey).

## [0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.0) - 2021-03-28

<small>[Compare with 0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.1...0.2.0)</small>

### Bug Fixes
- fix documentation failing ci ([4be75c2](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/4be75c2bf3d922696d97dd79993db2dd20f73c5a) by Michael Ramsey).
- change quality-template image to python:3.6 ([2d04f6b](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2d04f6b7965ae52f8b25e8e786002d6e833bdcbe) by Michael Ramsey).
- switched pages to python3.6 as pip keeps failing on python 3.8 for gitlab ([793f8fa](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/793f8fa2e687a44d5dfab96a410dabf97872d7ed) by Michael Ramsey).
- updated stuff to new general stuff to test gitlab CI for copier-poetry ([2b7ad36](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2b7ad364531283b5a633661cfbc1657354f51afa) by Michael Ramsey).
- reverted some changes so pages would properly deploy ([edf06b7](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/edf06b73b3de22dbded3b6f49fc1093db07cc1c4) by Michael Ramsey).
- added minor missing test action before coverage ([88b5939](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/88b593906eb5bfd96aa28553d2553ea589e547c5) by Michael Ramsey).
- tests and CI .gitlab-ci.yml to be more efficient ([60f46a1](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/60f46a18219c047a6b4d3d68c7eead897b79dca4) by Michael Ramsey).

### Features
- add dns lookup utils and new files ([f257827](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f257827eae87d535bbb3930b76a755c28e1a1ac9) by Michael Ramsey).

## [0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.1) - 2021-03-09

<small>[Compare with 0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.0...0.1.1)</small>

### Bug Fixes
- Updated duties.py to clean public ([5ab03dd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/5ab03dd793bc6bb1980947c08a6c4d4186fe428f) by Michael Ramsey).

## [0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.0) - 2021-03-09

<small>[Compare with first commit](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/b1b7ca3d1258efd0456dc46f62cb6cdddb45b060...0.1.0)</small>


## [0.2.2](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.2) - 2021-03-28

<small>[Compare with 0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.1...0.2.2)</small>

### Bug Fixes
- fixed asyncio issue with dnslookups when threaded without existing eventloop ([f1349fd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f1349fd849805e3570f6319dbeae10d343ef0736) by Michael Ramsey).


## [0.2.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.1) - 2021-03-28

<small>[Compare with 0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.2.0...0.2.1)</small>

### Bug Fixes
- fixed check-types ci failing and updated configs ([ff1a9b6](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/ff1a9b6c3d3dd32902f1bc2b0c9b1322d47e9150) by Michael Ramsey).


## [0.2.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.2.0) - 2021-03-28

<small>[Compare with 0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.1...0.2.0)</small>

### Bug Fixes
- fix documentation failing ci ([4be75c2](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/4be75c2bf3d922696d97dd79993db2dd20f73c5a) by Michael Ramsey).
- change quality-template image to python:3.6 ([2d04f6b](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2d04f6b7965ae52f8b25e8e786002d6e833bdcbe) by Michael Ramsey).
- switched pages to python3.6 as pip keeps failing on python 3.8 for gitlab ([793f8fa](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/793f8fa2e687a44d5dfab96a410dabf97872d7ed) by Michael Ramsey).
- updated stuff to new general stuff to test gitlab CI for copier-poetry ([2b7ad36](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/2b7ad364531283b5a633661cfbc1657354f51afa) by Michael Ramsey).
- reverted some changes so pages would properly deploy ([edf06b7](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/edf06b73b3de22dbded3b6f49fc1093db07cc1c4) by Michael Ramsey).
- added minor missing test action before coverage ([88b5939](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/88b593906eb5bfd96aa28553d2553ea589e547c5) by Michael Ramsey).
- tests and CI .gitlab-ci.yml to be more efficient ([60f46a1](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/60f46a18219c047a6b4d3d68c7eead897b79dca4) by Michael Ramsey).

### Features
- add dns lookup utils and new files ([f257827](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/f257827eae87d535bbb3930b76a755c28e1a1ac9) by Michael Ramsey).


## [0.1.1](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.1) - 2021-03-09

<small>[Compare with 0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/0.1.0...0.1.1)</small>

### Bug Fixes
- Updated duties.py to clean public ([5ab03dd](https://gitlab.com/mikeramsey/wizard-domaininfo/commit/5ab03dd793bc6bb1980947c08a6c4d4186fe428f) by Michael Ramsey).


## [0.1.0](https://gitlab.com/mikeramsey/wizard-domaininfo/tags/0.1.0) - 2021-03-09

<small>[Compare with first commit](https://gitlab.com/mikeramsey/wizard-domaininfo/compare/b1b7ca3d1258efd0456dc46f62cb6cdddb45b060...0.1.0)</small>

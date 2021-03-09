# Wizard Domaininfo

[![pipeline status](https://gitlab.com/mikeramsey/wizard-domaininfo/badges/master/pipeline.svg)](https://gitlab.com/mikeramsey/wizard-domaininfo/pipelines)
[![coverage report](https://gitlab.com/mikeramsey/wizard-domaininfo/badges/master/coverage.svg)](https://gitlab.com/mikeramsey/wizard-domaininfo/commits/master)
[![documentation](https://img.shields.io/badge/docs-mkdocs%20material-blue.svg?style=flat)](https://mikeramsey.gitlab.io/wizard-domaininfo/)
[![pypi version](https://img.shields.io/pypi/v/wizard-domaininfo.svg)](https://pypi.org/project/wizard-domaininfo/)
[![gitter](https://badges.gitter.im/join%20chat.svg)](https://gitter.im/wizard-domaininfo/community)

DNS/Whois Domain Information library

## Requirements

Wizard Domaininfo requires Python 3.6 or above.

<details>
<summary>To install Python 3.6, I recommend using <a href="https://github.com/pyenv/pyenv"><code>pyenv</code></a>.</summary>

```bash
# install pyenv
git clone https://github.com/pyenv/pyenv ~/.pyenv

# setup pyenv (you should also put these three lines in .bashrc or similar)
export PATH="${HOME}/.pyenv/bin:${PATH}"
export PYENV_ROOT="${HOME}/.pyenv"
eval "$(pyenv init -)"

# install Python 3.6
pyenv install 3.6.12

# make it available globally
pyenv global system 3.6.12
```
</details>

## Installation

With `pip`:
```bash
python3.6 -m pip install wizard_domaininfo
```

With [`pipx`](https://github.com/pipxproject/pipx):
```bash
python3.6 -m pip install --user pipx

pipx install --python python3.6 wizard_domaininfo
```

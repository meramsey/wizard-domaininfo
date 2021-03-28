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

=========

A WHOIS DNS retrieval and parsing library for Python.

## Dependencies

None! All you need is the Python standard library. Optional RDAP WHOIS based lookups require requests and json libraries. Optional DNS lookups are based on aiodns library.

## Instructions

The whois legacy manual HTML version is also viewable [here](http://cryto.net/pythonwhois).
The new manual for RDAP based whois and DNS is located [here](https://mikeramsey.gitlab.io/wizard-domaininfo/).
## Goals

* 100% coverage of WHOIS/DNS formats.
* Accurate and complete data.
* Consistently functional parsing; constant tests to ensure the parser isn't accidentally broken.

## Features

* WHOIS data retrieval
	* Able to follow WHOIS server redirects
	* Won't get stuck on multiple-result responses from verisign-grs
* WHOIS data parsing
	* Base information (registrar, etc.)
	* Dates/times (registration, expiry, ...)
	* Full registrant information (!)
	* Nameservers
* Optional WHOIS data normalization
	* Attempts to intelligently reformat WHOIS data for better (human) readability
	* Converts various abbreviation types to full locality names
		* Airport codes
		* Country names (2- and 3-letter ISO codes)
		* US states and territories
		* Canadian states and territories
		* Australian states
* `pwhois`, a simple WHOIS tool using pythonwhois
	* Easily readable output format
	* Can also output raw WHOIS data
	* ... and JSON.
* Automated testing suite for parse.py and legacy whois(non rdap based)
	* Will detect and warn about any changes in parsed data compared to previous runs
	* Guarantees that previously working WHOIS parsing doesn't unintentionally break when changing code
* Automated testing suite for rdap and aiodns is based on pytest
* Fast Asynchronous DNS lookups via c-ares aiodns library and helper methods in utils.py.
* Single call via DomainInfo class in domaininfo.py will get all available DNS/Whois via rdap and fallback to legacy whois as needed.
	* Checks for WAFs(Cloudflare/Sucuri/Quic.Cloud)
	* Check domain expiration.
	* Check for or enumerate DKIM records and selectors.
	* Check Whois Nameservers and DNS nameservers match.
	* See [here](https://gitlab.com/mikeramsey/wizard-domaininfo/-/blob/master/src/wizard_domaininfo/domaininfo.py#L23-69) for all the class attributes.
	

## Important update notes


## It doesn't work!

* It doesn't work at all?
* It doesn't parse the data for a particular domain?
* There's an inaccuracy in parsing the data for a domain, even just a small one?

If any of those apply, don't hesitate to file an issue! The goal is 100% coverage, and we need your feedback to reach that goal.

## License

This library may be used under the MIT License.

## Data sources

This library uses a number of third-party datasets for normalization:

* `airports.dat`: [OpenFlights Airports Database](http://openflights.org/data.html) ([Open Database License 1.0](http://opendatacommons.org/licenses/odbl/1.0/), [Database Contents License 1.0](http://opendatacommons.org/licenses/dbcl/1.0/))
* `countries.dat`: [Country List](https://github.com/umpirsky/country-list) (MIT license)
* `countries3.dat`: [ISO countries list](https://gist.github.com/eparreno/205900) (license unspecified)
* `states_au.dat`: Part of `pythonwhois` (WTFPL/CC0)
* `states_us.dat`: [State Table](http://statetable.com/) (license unspecified, free reuse encouraged)
* `states_ca.dat`: [State Table](http://statetable.com/) (license unspecified, free reuse encouraged)

Be aware that the OpenFlights database in particular has potential licensing consequences; if you do not wish to be bound by these potential consequences, you may simply delete the `airports.dat` file from your distribution. `pythonwhois` will assume there is no database available, and will not perform airport code conversion (but still function correctly otherwise). This also applies to other included datasets.

## Contributing

Feel free to fork and submit pull requests (to the `develop` branch)! If you change any parsing or normalization logic, ensure to run the full test suite before opening a pull request. Instructions for that are below.

Please note that this project uses tabs for indentation.

All commands are relative to the root directory of the repository.

**Pull requests that do _not_ include output from test_parse.py will be rejected!**

### Adding new WHOIS data to the testing set

	pwhois --raw thedomain.com > test/data/thedomain.com
	
### Checking the currently parsed data (while editing the parser)

	./pwhois -f test/data/thedomain.com/ .
	
(don't forget the dot at the end!)
	
### Marking the current parsed data as correct for a domain

Make sure to verify (using `pwhois` or otherwise) that the WHOIS data for the domain is being parsed correctly, before marking it as correct!

	python test_parse.py update thedomain.com
	
### Running all tests

	python test_parse.py run all
	
### Testing a specific domain

	python test_parse.py run thedomain.com
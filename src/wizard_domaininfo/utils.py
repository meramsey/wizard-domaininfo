import aiodns
import asyncio
import json
import requests
import wizard_whois
from requests.exceptions import Timeout, ConnectionError
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter


# https://findwork.dev/blog/advanced-usage-python-requests-timeouts-retries-hooks/
class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        """The HTTPAdapter is comparable we can combine retries and timeouts.

        :param *args: args
        :type *args: mixed
        :param **kwargs: Some kwargs
        :type **kwargs: mixed
        """
        DEFAULT_TIMEOUT = 1
        self.timeout = DEFAULT_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        """Send a request via TimeoutHTTPAdapter.

        Args:
            request (): request
            **kwargs (): kwargs

        Returns: Boolean

        """
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


http = requests.Session()
# Mount  TimeoutHTTP adapter with retries it for both http and https usage
adapter = TimeoutHTTPAdapter(timeout=2.5)
retries = Retry(total=1, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
http.mount("https://", TimeoutHTTPAdapter(max_retries=retries))
http.mount("http://", TimeoutHTTPAdapter(max_retries=retries))

TIMEOUT = 1.0  # timeout in seconds
rdapbootstrapurl = "https://www.rdap.net/"

wizard_whois.net.socket.setdefaulttimeout(TIMEOUT)


def check_http_reachable(domain_name):
    """Check if the domain is reachable via http.

    :param domain_name: Domain name to check is reachable.
    :type domain_name: str
    :return: Returns `True` if connectable, `False` otherwise
    :rtype: bool
    """
    try:
        if "http" not in domain_name:
            url = "http://" + domain_name
        http.get(url)
        return True
    except requests.exceptions.ConnectionError:
        print(f"URL {url} not reachable")
        return False


def check_url_ssl(domain_name):
    """Check if the domain has a valid SSL certificate.

    :param domain_name: Domain name to check SSL for.
    :type domain_name: str
    :return: Returns `True` if valid, `False` otherwise
    :rtype: bool
    """
    try:
        if "http" not in domain_name:
            url = "https://" + domain_name
        else:
            url = domain_name
        http.get(url, verify=True)
        return True
    except requests.exceptions.ConnectionError:
        print(f"URL {url} not reachable or SSL expired")
        return False


loop = asyncio.get_event_loop()
resolver = aiodns.DNSResolver(loop=loop)


async def query(name, query_type):
    return await resolver.query(name, query_type)


def get_hostname_from_ip(ip):
    """Basic get RDNS via PTR lookup.

    :param ip: IP address to lookup
    :type ip: str
    :return: Returns `hostname` if found, or empty string '' otherwise
    :rtype: str
    """
    try:
        reverse_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        coro = query(reverse_name, "PTR")
        result = loop.run_until_complete(coro)
        return result.name
    except:
        return ""


def get_rdns_from_ip(ip):
    """Basic get RDNS via gethostbyaddr.

    :param ip: IP address to lookup
    :type ip: str
    :return: Returns `hostname` if found, or empty string '' otherwise
    :rtype: str
    """
    try:
        coro = resolver.gethostbyaddr(ip)
        result = loop.run_until_complete(coro)
        return result.name
    except:
        return ""


def get_domain_whois_info_legacy(domain):
    """Do WHOIS lookup via legacy method via wizard_whois.

    :param domain: Domain to lookup whois for
    :type domain: str
    :return: Dictionary of domain whois information
    :rtype: dict, bool
    """
    try:
        domain_whois = wizard_whois.get_whois(domain)
        # print(domain_whois)
        return domain_whois
    except:
        return False


def get_domain_whois_expiration_date_legacy(domain):
    """Get a domains whois expiration date via legacy method via wizard_whois.

    :param domain: Domain to lookup whois expiration for
    :type domain: str
    :return: Dictionary of domain whois information
    :rtype: dict, bool
    """
    try:
        domain_whois = wizard_whois.get_whois(domain)
        # print(domain_whois)
        return str(domain_whois["expiration_date"][0])
    except:
        return False


def get_domain_rdap_info(domain):
    """Do WHOIS lookup via rdap method.

    :param domain: Domain to lookup whois for
    :type domain: str
    :return: Dictionary of domain whois information
    :rtype: dict, bool
    """
    request = rdapbootstrapurl + "domain/" + domain
    try:
        domain_response = http.get(request).text
        # print(request)
        # print(domain_response)
        domain_whois = json.loads(str(domain_response))
        # print(json.dumps(self.domain_whois, indent=4))
        return domain_whois
    except:
        print("RDAP Lookup Failed")
        return False


def get_domain_whois_event_date_rdap(domain, event_action):
    """Get Domain whois event date from rdap.

    :param domain: Domain
    :type domain: str
    :param event_action: str Supported events: expiration, registration
    :type event_action: str
    :return: Date formatted "%Y-%m-%d %H:%M:%S" Example: '1997-09-15 04:00:00' or False
    :rtype: str
    """
    domain_whois = get_domain_rdap_info(domain)
    for event in domain_whois["events"]:
        # print(event["eventAction"], event["eventDate"])
        if event["eventAction"] == event_action:
            return event["eventDate"].replace("T", " ").replace("Z", "")


def get_domain_whois_expiration_date_rdap(domain):
    """Get domain whois expiration date from rdap.

    :param domain: Domain
    :type domain: str
    :return: Date formatted "%Y-%m-%d %H:%M:%S" Example: '1997-09-15 04:00:00' or False
    :rtype: str
    """
    return get_domain_whois_event_date_rdap(domain, "expiration")


def get_domain_whois_registration_date_rdap(domain):
    """Get domain whois registration date from rdap.

    :param domain: Domain
    :type domain: str
    :return: Date formatted "%Y-%m-%d %H:%M:%S" Example: '1997-09-15 04:00:00' or False
    :rtype: str
    """
    return get_domain_whois_event_date_rdap(domain, "registration")


# print(get_hostname_from_ip("1.1.1.1"))
# print(get_rdns_from_ip("8.8.8.8"))
# print(get_domain_whois_info_legacy("google.com"))
# print(get_domain_whois_expiration_date_legacy("google.com"))
# print(get_domain_rdap_info("google.com"))
# print(get_domain_whois_registration_date_rdap("google.com"))
# print(get_domain_whois_expiration_date_rdap("google.com"))
# print(get_domain_whois_event_date_rdap("google.com", "expiration"))
# print(get_domain_whois_event_date_rdap("google.com", "registration"))

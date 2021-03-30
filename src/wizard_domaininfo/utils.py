from datetime import datetime
import aiodns
import asyncio
import json
import requests
from dateutil.parser import parse as date_parse
from requests.exceptions import Timeout, ConnectionError
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from wizard_domaininfo import get_whois, net as wizard_whois, parse


# https://findwork.dev/blog/advanced-usage-python-requests-timeouts-retries-hooks/
class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        """
        The HTTPAdapter class combines retries and timeouts for the requests library.

        Args:
            *args ():
            **kwargs ():
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
url = ''

wizard_whois.socket.setdefaulttimeout(TIMEOUT)


def get_or_create_eventloop():
    try:
        return asyncio.get_event_loop()
    except RuntimeError as ex:
        if "There is no current event loop in thread" in str(ex):
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return asyncio.get_event_loop()


def parse_date_convert(date, fmt=None):
    """Parse date from string and convert to desired format.

    :param date: Date to parse
    :type date: str
    :param fmt: Datetime format to convert to
    :type fmt: str
    :return: Returns parsed and converted datetime in a string otherwise `None`
    :rtype: str
    """
    if fmt is None:
        fmt = '%Y-%m-%d %H:%M:%S'
    if date is None:
        return False
    get_date_obj = date_parse(str(date))
    fmt_date = str(get_date_obj.strftime(fmt))
    return fmt_date


def check_http_reachable(domain_name):
    """Check if the domain is reachable via http.

    :param domain_name: Domain name to check is reachable.
    :type domain_name: str
    :return: Returns `True` if connectable, `False` otherwise
    :rtype: bool
    """
    global url
    try:
        if "http" not in domain_name:
            url = "http://" + domain_name
        else:
            url = domain_name
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
    global url
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
    """Do WHOIS lookup via legacy method via whois socket.

    :param domain: Domain to lookup whois for
    :type domain: str
    :return: Dictionary of domain whois information
    :rtype: dict, bool
    :Example:
    >>> print(get_domain_whois_info_legacy('google.com'))
    `{'id': ['2138514_DOMAIN_COM-VRSN'], 'status': ['clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited', 'clientTransferProhibited https://icann.org/epp#clientTransferProhibited', 'clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited', 'serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited', 'serverTransferProhibited https://icann.org/epp#serverTransferProhibited', 'serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited'], 'creation_date': [datetime.datetime(1997, 9, 15, 4, 0)], 'expiration_date': [datetime.datetime(2028, 9, 14, 4, 0)], 'updated_date': [datetime.datetime(2019, 9, 9, 15, 39, 4)], 'registrar': ['MarkMonitor Inc.'], 'whois_server': ['whois.markmonitor.com'], 'nameservers': ['NS1.GOOGLE.COM', 'NS2.GOOGLE.COM', 'NS3.GOOGLE.COM', 'NS4.GOOGLE.COM'], 'emails': ['abusecomplaints@markmonitor.com'], 'contacts': {'registrant': None, 'tech': None, 'admin': None, 'billing': None}, 'raw': ['   Domain Name: GOOGLE.COM\n   Registry Domain ID: 2138514_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.markmonitor.com\n   Registrar URL: http://www.markmonitor.com\n   Updated Date: 2019-09-09T15:39:04Z\n   Creation Date: 1997-09-15T04:00:00Z\n   Registry Expiry Date: 2028-09-14T04:00:00Z\n   Registrar: MarkMonitor Inc.\n   Registrar IANA ID: 292\n   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\n   Registrar Abuse Contact Phone: +1.2083895740\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS1.GOOGLE.COM\n   Name Server: NS2.GOOGLE.COM\n   Name Server: NS3.GOOGLE.COM\n   Name Server: NS4.GOOGLE.COM\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2021-03-27T21:37:18Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar\'s sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant\'s agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar\'s Whois database to\nview the registrar\'s reported date of expiration for this registration.\n\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices\' ("VeriSign") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.\n']}`
    """
    try:
        domain_whois = get_whois(domain)
        # print(domain_whois)
        return domain_whois
    except:
        return False


def get_domain_whois_expiration_date_legacy(domain):
    """Get a domains whois expiration date via legacy method via whois socket.

    :param domain: Domain to lookup whois expiration for
    :type domain: str
    :return: Dictionary of domain whois information
    :rtype: dict, bool
    :Example:
    >>> print(get_domain_whois_expiration_date_legacy('google.com'))
    2028-09-14 04:00:00
    """
    try:
        domain_whois = get_whois(domain)
        # print(domain_whois)
        # print(str(domain_whois["expiration_date"][0]))
        # return parse_date_convert(str(domain_whois["expiration_date"][0]))
        return str(domain_whois["expiration_date"][0])
    except:
        return False


def get_domain_rdap_info(domain):
    """Do WHOIS lookup via rdap method.

    :param domain: Domain to lookup whois for
    :type domain: str
    :return: Dictionary of domain whois information
    :rtype: dict, bool
    :Example:
    >>> print(get_domain_rdap_info('google.com'))
    `{'objectClassName': 'domain', 'handle': '2138514_DOMAIN_COM-VRSN', 'ldhName': 'GOOGLE.COM', 'links': [{'value': 'https://rdap.verisign.com/com/v1/domain/GOOGLE.COM', 'rel': 'self', 'href': 'https://rdap.verisign.com/com/v1/domain/GOOGLE.COM', 'type': 'application/rdap+json'}, {'value': 'https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM', 'rel': 'related', 'href': 'https://rdap.markmonitor.com/rdap/domain/GOOGLE.COM', 'type': 'application/rdap+json'}], 'status': ['client delete prohibited', 'client transfer prohibited', 'client update prohibited', 'server delete prohibited', 'server transfer prohibited', 'server update prohibited'], 'entities': [{'objectClassName': 'entity', 'handle': '292', 'roles': ['registrar'], 'publicIds': [{'type': 'IANA Registrar ID', 'identifier': '292'}], 'vcardArray': ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'MarkMonitor Inc.']]], 'entities': [{'objectClassName': 'entity', 'roles': ['abuse'], 'vcardArray': ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', ''], ['tel', {'type': 'voice'}, 'uri', 'tel:+1.2083895740'], ['email', {}, 'text', 'abusecomplaints@markmonitor.com']]]}]}], 'events': [{'eventAction': 'registration', 'eventDate': '1997-09-15T04:00:00Z'}, {'eventAction': 'expiration', 'eventDate': '2028-09-14T04:00:00Z'}, {'eventAction': 'last update of RDAP database', 'eventDate': '2021-03-27T09:24:47Z'}], 'secureDNS': {'delegationSigned': False}, 'nameservers': [{'objectClassName': 'nameserver', 'ldhName': 'NS1.GOOGLE.COM'}, {'objectClassName': 'nameserver', 'ldhName': 'NS2.GOOGLE.COM'}, {'objectClassName': 'nameserver', 'ldhName': 'NS3.GOOGLE.COM'}, {'objectClassName': 'nameserver', 'ldhName': 'NS4.GOOGLE.COM'}], 'rdapConformance': ['rdap_level_0', 'icann_rdap_technical_implementation_guide_0', 'icann_rdap_response_profile_0'], 'notices': [{'title': 'Terms of Use', 'description': ['Service subject to Terms of Use.'], 'links': [{'href': 'https://www.verisign.com/domain-names/registration-data-access-protocol/terms-service/index.xhtml', 'type': 'text/html'}]}, {'title': 'Status Codes', 'description': ['For more information on domain status codes, please visit https://icann.org/epp'], 'links': [{'href': 'https://icann.org/epp', 'type': 'text/html'}]}, {'title': 'RDDS Inaccuracy Complaint Form', 'description': ['URL of the ICANN RDDS Inaccuracy Complaint Form: https://icann.org/wicf'], 'links': [{'href': 'https://icann.org/wicf', 'type': 'text/html'}]}]}`
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


def get_domain_whois_event_date_rdap(domain, event_action, rdap_dict=None):
    """Get Domain whois event date from rdap.

    :param domain: Domain
    :type domain: str
    :param event_action: str Supported events: expiration, registration
    :type event_action: str
    :return: Date formatted "%Y-%m-%d %H:%M:%S" Example: '1997-09-15 04:00:00' or False
    :rtype: str
    :Example:
    >>> print(get_domain_whois_event_date_rdap('google.com', 'expiration'))
    2028-09-14 04:00:00
    """
    if rdap_dict is None:
        domain_whois = get_domain_rdap_info(domain)
    else:
        domain_whois = rdap_dict

    if domain_whois:
        for event in domain_whois["events"]:
            # print(event["eventAction"], event["eventDate"])
            if event["eventAction"] == event_action:
                # print(str(event["eventDate"]))
                return parse_date_convert(str(event["eventDate"]))
    else:
        return False


def get_domain_whois_expiration_date_rdap(domain):
    """Get domain whois expiration date from rdap.

    :param domain: Domain
    :type domain: str
    :return: Date formatted "%Y-%m-%d %H:%M:%S" Example: '1997-09-15 04:00:00' or False
    :rtype: str
    :Example:
    >>> print(get_domain_whois_expiration_date_rdap("google.com"))
    2028-09-14 04:00:00
    """
    return get_domain_whois_event_date_rdap(domain, "expiration")


def get_domain_whois_registration_date_rdap(domain):
    """Get domain whois registration date from rdap.

    :param domain: Domain
    :type domain: str
    :return: Date formatted "%Y-%m-%d %H:%M:%S" Example: '1997-09-15 04:00:00' or False
    :rtype: str
    :Example:
    >>> print(get_domain_whois_registration_date_rdap("google.com"))
    1997-09-15 04:00:00
    """
    return get_domain_whois_event_date_rdap(domain, "registration")


def get_ns_records(name):
    """Get NS(Nameserver) records for the name provided.

    :param name: Domain to lookup NS records for.
    :type name: str
    :return: Returns a list of the sorted NS records for the domain otherwise `None`.
    :rtype: list
    :Example:
    >>> print(get_ns_records("google.com"))
    `['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com']`
    """
    ns = []
    try:
        coro = query(str(name).lower(), 'NS')
        res_ns = loop.run_until_complete(coro)
        for elem in res_ns:
            ns.append(str(elem.host))
        ns = sorted(ns)
    except:
        ns = None
    return ns


def get_soa_record(name):
    """Get SOA(Start of Authority) record for the name provided.

    :param name: Domain to get SOA record for.
    :type name: str
    :return: Returns a dictionary with the SOA information otherwise `None`.
    :rtype: dict
    :Example:
    >>> print(get_soa_record("google.com"))
    `{'SOA': {'nsname': 'ns1.google.com', 'hostmaster': 'dns-admin.google.com', 'serial': '365213266', 'refresh': '900', 'retry': '900', 'expires': '1800', 'minttl': '60', 'ttl': '13'}}`
    """
    try:
        coro = query(str(name).lower(), 'SOA')
        res_soa = loop.run_until_complete(coro)
        soa_dict = {"SOA": {"nsname": str(res_soa.nsname), "hostmaster": str(res_soa.hostmaster),
                            "serial": str(res_soa.serial),
                            "refresh": str(res_soa.refresh), "retry": str(res_soa.retry),
                            "expires": str(res_soa.expires),
                            "minttl": str(res_soa.minttl), "ttl": str(res_soa.ttl)}}
    except:
        soa_dict = None
    return soa_dict


def get_a_record(name):
    """Get A record(IPv4 address) for the name provided.

    :param name: Hostname to find A record/IP for.
    :type name: str
    :return: Returns an A record also known as an IPv4 address otherwise `None`
    :rtype: str
    :Example:
    >>> print(get_a_record("google.com"))
    172.217.15.206
    """
    try:
        coro = query(str(name).lower(), 'A')
        result = loop.run_until_complete(coro)
        ip = str(result[0].host)
    except:
        ip = None
    return ip


def get_aaaa_record(name):
    """Get AAAA record(IPv6 address) for the name provided.

    :param name: Hostname to find AAAA record/IP for.
    :type name: str
    :return: Returns an AAAA record also known as an IPv6 address otherwise `None`
    :rtype: str
    :Example:
    >>> print(get_aaaa_record("google.com"))
    2607:f8b0:4008:813::200e
    """
    try:
        coro = query(str(name).lower(), 'AAAA')
        result = loop.run_until_complete(coro)
        ipv6 = str(result[0].host)
    except:
        ipv6 = None
    return ipv6


def get_cname_record(name):
    """Get A record(IPv4 address) for the name provided.

    :param name: Hostname to find A record/IP for.
    :type name: str
    :return: Returns an A record also known as an IPv4 address otherwise `None`
    :rtype: str
    :Example:
    >>> print(get_a_record("google.com"))
    172.217.15.206
    """
    try:
        coro = query(str(name).lower(), 'CNAME')
        result = loop.run_until_complete(coro)
        ip = str(result[0].host)
    except:
        ip = None
    return ip


def get_txt_records(name):
    """Get TXT records for the domain provided.

    :param name: Domain to find TXT record for.
    :type name: str
    :return: Returns a list of TXT records
    :rtype: list
    :Example:

    >>> print(get_txt_records("google.com"))
    `[['TXT', 'google.com', 'facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95'], ['TXT', 'google.com', 'apple-domain-verification=30afIBcvSuDV2PLX'], ['TXT', 'google.com', 'v=spf1 include:_spf.google.com ~all'], ['TXT', 'google.com', 'globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8='], ['TXT', 'google.com', 'docusign=1b0a6754-49b1-4db5-8540-d2c12664b289'], ['TXT', 'google.com', 'docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e'], ['TXT', 'google.com', 'google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o']]`
    """
    txt_records = []
    try:
        res_txt = loop.run_until_complete(resolver.query(name, 'TXT'))
        for elem in res_txt:
            # print(str(elem.text))
            txt_records.append(['TXT', str(name), str(elem.text)])
    except:
        txt_records = None
    return txt_records


def get_mx_records(name):
    """Get MX records for the domain provided.

    :param name: Domain to find MX records for.
    :type name: str
    :return: Returns a list of MX records
    :rtype: list
    :Example:
    >>> print(get_mx_records("wizardassistant.com"))
    `[<ares_query_mx_result> host=mail.wizardassistant.com, priority=10, ttl=244, <ares_query_mx_result> host=zimbra.wizardassistant.com, priority=0, ttl=244]`
    """
    res_mx = []
    try:
        res_mx = loop.run_until_complete(resolver.query(name, 'MX'))
    except:
        pass
    return res_mx


def get_dkim_records(name, select=None):
    """Get DKIM records for a domain.

    :param name: Domain name
    :type name: str
    :param select: Optional: Selector that can be also searched for.
    :type select: str
    :return: Returns a dictionary of dkim selectors as keys and their records as values.
    :rtype: dict
    :Example:
    >>> print(str(get_dkim_records('wizardassistant.com')))
    {'default._domainkey.wizardassistant.com': 'v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAynF/0vOKHvSzZyDNW9wIbdv7D8zhPZ4624JYt9YvyIV3EcNRMX0RSi7KyLCVvjVrOoWXHx5NPoXt5OM2hRXb+cTUYAj4tijuDUzkRjmXFEbHhdrQFholM5FF/nb4i5MnSyVUrOGcj0Wxjmt1y1KQn5U/HSrZP0bk3FnjCHcQ62prCgFGsum44crI2efIm8yPwWFaDzDE/xjn218BY8PuMiNu4LYznmdfXDDJeRa7U+uuLAz0diiAYgwNPGiN6RYPum2yyixdDawxB1R3qWpGnAfGj9Tpl045ALJCjUsh7l7C3PmcSXc8Ez8WPCgYqs8zOKHwwYi3ILTH12x1JxicpwIDAQAB'}

    """
    dkim = {}
    # Common selectors for rapid enumeration
    dkim_selectors = ['default', 'dkim', 'dkim1', 'google', 'k1', 'k2', 'mail', 'selector1', 'selector2', 'zoho']

    # If one is provided add it to the list
    if select is not None:
        dkim_selectors.append(str(select))

    try:
        # Here we are checking all the popular and common DKIM selector names in a loop plus any specific one provided
        for selector in dkim_selectors:
            # default._domainkey.domain.com
            # DKIM query the host's DNS
            dkim_name = f'{selector}._domainkey.{name}'
            res_dkim = loop.run_until_complete(resolver.query(dkim_name, 'TXT'))
            for elem in res_dkim:
                if 'v=DKIM' in str(elem.text):
                    dkim[str(dkim_name)] = str(elem.text)
    except:
        # we pass here so that the loop can keep trying till its tried them all
        pass

    return dkim


def get_dmarc_record(name):
    """Get DMARC record for domain.

    :param name: Domain name to get DMARC record for.
    :type name: str
    :return: Returns the string form of the DMARC record value if successful otherwise `None`.
    :rtype: str
    :Example:
    >>> print(get_dmarc_record("google.com"))
    v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com
    """
    # _dmarc.domain.com
    dmarc_name = '_dmarc.' + name
    dmarc = None
    try:
        # DMARC query the host's DNS
        res_dmarc = loop.run_until_complete(resolver.query(dmarc_name, 'TXT'))

        for elem in res_dmarc:
            if 'v=DMARC' in str(elem.text):
                dmarc = str(elem.text)
    except:
        pass
    return dmarc


def check_domain_expired(expiration_date, fmt=None):
    """Check if domain expiration date has passed.
    :param expiration_date: Expiration datetime to check
    :type expiration_date: str
    :param fmt: Datetime format to convert to when checking
    :type fmt: datetime format string like: '%Y-%m-%d %H:%M:%S'
    :return: Returns True if expired
    :rtype: bool
    :Example:
    >>> print(check_domain_expired('2028-09-14 04:00:00'))
    False
    """
    if fmt is None:
        fmt = '%Y-%m-%d %H:%M:%S'
    try:
        past = datetime.strptime(str(expiration_date), fmt)
        present = datetime.now()
        if past.date() < present.date():
            # print('Domain is expired')
            return True
        else:
            # print('Domain is not expired')
            return False
    except:
        return True
        pass

# print(get_mx_records("wizardassistant.com"))
# print(check_domain_expired('2028-09-14 04:00:00'))
# print(get_dmarc_record("google.com"))
# print(str(get_dkim_records('wizardassistant.com')))

# print(parse_date_convert('2028-09-14T04:00:00Z'))
# print(get_domain_whois_info_legacy('wizardassistant.com'))
# print(get_domain_whois_expiration_date_legacy("wizardassistant.com"))
# print(get_domain_whois_info_legacy('wizardassistant.app'))
# print(get_domain_whois_expiration_date_legacy("google.com"))
# print(get_domain_whois_expiration_date_rdap("google.com"))
# print(get_a_record("google.com"))
# print(get_aaaa_record("google.com"))
# print(get_ns_records("google.com"))
# print(get_soa_record("google.com"))

# print(get_domain_whois_info_legacy("google.com.au"))
# print(get_domain_whois_expiration_date_rdap("google.com"))
# test commands
# print(get_hostname_from_ip("1.1.1.1"))
# print(get_rdns_from_ip("8.8.8.8"))
# print(get_domain_whois_info_legacy("google.com"))

# print(get_domain_rdap_info("google.com"))
# print(get_domain_whois_registration_date_rdap("google.com"))
# print(get_domain_whois_expiration_date_rdap("wizardassistant.com"))
# print(get_domain_whois_expiration_date_rdap("wizardassistant.app"))
# print(get_domain_whois_event_date_rdap("google.com", "expiration"))
# print(get_domain_whois_event_date_rdap("google.com", "registration"))
# print(get_domain_whois_expiration_date_rdap("google.com"))

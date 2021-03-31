import json
import timeit
import aiodns
import asyncio
from datetime import date, datetime
from collections import defaultdict
import wizard_domaininfo
from wizard_domaininfo.utils import get_dmarc_record, get_a_record, get_soa_record, get_aaaa_record, get_ns_records, \
    get_txt_records, get_hostname_from_ip, get_rdns_from_ip, get_domain_rdap_info, get_domain_whois_info_legacy, \
    parse_date_convert, get_dkim_records, check_domain_expired, get_cname_record, get_mx_records, \
    get_or_create_eventloop

TIMEOUT = 1.0  # timeout in seconds
wizard_domaininfo.net.socket.setdefaulttimeout(TIMEOUT)
url = ''


class DomainInfo:
    DEFAULT_TIMEOUT = 1  # seconds
    rdapbootstrapurl = 'https://www.rdap.net/'
    wizard_domaininfo.net.socket.setdefaulttimeout(DEFAULT_TIMEOUT)
    default_resolvers = ['1.1.1.1', '8.8.8.8', '1.0.0.1', '8.8.4.4']

    def __init__(self, domain):
        self.name = domain
        self.domain = domain
        # Setup dictionary and defaults
        self.domain = domain.lower()
        self.url = 'http://' + self.domain
        self.domain_dict = defaultdict(set)
        self.domain_whois = defaultdict(set)
        self.registrar = ''
        self.registration = ''
        self.expiration = ''
        self.status = ''
        self.soa = {}
        self.whois_statuses = []
        # Setup lists variables
        # Nameservers with A record lookups
        self.whois_nameservers = []
        self.domain_nameservers = []
        # Domain WWW: A, AAA, CNAME values
        self.domain_www = []
        # Domain MX Records list
        self.domain_mx = []
        # Domain TXT type records
        self.domain_txt = []
        # Nameserver lists without IP's
        self.whois_ns = []
        self.ns = []
        # Abort DNS lookups when no valid DNS NS found to prevent lockups
        self.dns_lookup_continue = ''
        # Force DNS lookups when using custom resolver: todo
        self.dns_lookup_force = ''
        # Domain Expired
        self.expired = ''
        # Domain DNS Dictionary
        self.dns = defaultdict(set)
        # Whois and DNS NS agree on Nameserver names
        self.auth_ns_match = ''
        # Sender Policy Framework
        self.spf = ''
        # DomainKeys Identified Mail (DKIM)
        self.dkim = []
        # Domain-based Message Authentication, Reporting & Conformance (DMARC)
        self.dmarc = ''
        # Holds values for detected WAF's/CDN/Proxy like Sucuri/Cloudflare/Quic.cloud
        self.waf = ''
        # DNSSEC aka SecureDNS status of domain
        self.dnssec = ''
        # Setup asyncio
        self.loop = get_or_create_eventloop()
        self.resolver = aiodns.DNSResolver(loop=self.loop)
        self.custom_resolvers = []
        self.resolver.nameservers = self.default_resolvers
        self.rdap_url = self.rdapbootstrapurl + "domain/" + domain

        # Initialize Whois and DNS
        self.get_whois_domain()
        self.check_expiration()
        self.get_domain_dns()
        self.check_auth_nameservers_match()

    async def query(self, name, query_type):
        return await self.resolver.query(name, query_type)

    def get_domain_whois_info(self):

        try:
            self.domain_whois = get_domain_whois_info_legacy(self.domain)
            # print(self.domain_whois)
        except:
            return False
            # pass

        # "WHOIS": {"status": "['client delete prohibited', 'server transfer prohibited', 'server update prohibited']"
        try:
            # print(str(self.domain_whois['status'][0]).rsplit())
            whois_status = self.domain_whois['status']
            # print(whois_status)
            for status in whois_status:
                status = status.rsplit()
                # print(status[0])
                self.whois_statuses.append(status[0])
            self.status = self.whois_statuses[0]
        except:
            self.status = 'No Status Found'
            pass

        # Source "WHOIS": {"registration": "1997-09-15T04:00:00Z", "expiration": "2028-09-14T04:00:00Z"}
        try:
            self.registration = parse_date_convert(str(self.domain_whois['creation_date'][0]))
        except:
            pass

        try:
            self.expiration = parse_date_convert(str(self.domain_whois['expiration_date'][0]))
        except:
            self.expired = False
            self.expiration = 'No Expiration Found'
            pass

        # "WHOIS": {"registrar": "MarkMonitor Inc."}
        try:
            self.registrar = str(self.domain_whois['registrar'][0])
        except:
            pass

        # "WHOIS": {"secureDNS": {"delegationSigned": false}}
        try:
            domainwhois_dnssec_raw = str(self.domain_whois['raw']).split('DNSSEC: ', 1)[1]
            # print(domainwhois_dnssec_raw)
            if "signedDelegation" in domainwhois_dnssec_raw:
                self.dnssec = True
            elif "unsigned" in domainwhois_dnssec_raw:
                self.dnssec = False
        except:
            pass

        #  "WHOIS": {"nameservers": [["NS1.GOOGLE.COM", "216.239.32.10"], ["NS2.GOOGLE.COM", "216.239.34.10"]]}
        try:
            for nameserver in self.domain_whois['nameservers']:
                # print(ns)
                ns = nameserver.lower()
                ip = get_a_record(ns)
                # print(ns, ip)
                self.whois_nameservers.append([str(ns), str(ip)])
                self.whois_ns.append(ns)
        except:
            pass

    def check_expiration(self):
        if not self.expiration == 'No Expiration Found':
            if check_domain_expired(self.expiration):
                self.expired = True
            else:
                self.expired = False

    def create_domain_dict_rdap(self):
        # "WHOIS": {"registrar": "MarkMonitor Inc."}
        try:
            self.registrar = str(self.domain_whois["entities"][0]['vcardArray'][1][1][3])
        except:
            pass

        # "WHOIS": {"status": "['client delete prohibited', 'server transfer prohibited', 'server update prohibited']"
        try:
            whois_status = self.domain_whois['status']
            for status in whois_status:
                self.whois_statuses.append(status)
            self.status = self.whois_statuses[0]
        except:
            pass

        # "WHOIS": {"registration": "1997-09-15T04:00:00Z", "expiration": "2028-09-14T04:00:00Z"}
        try:
            for event in self.domain_whois['events']:
                # print(event)
                event_action = event['eventAction']
                event_date = parse_date_convert(str(event["eventDate"]))
                if event_action == 'registration':
                    self.registration = event_date
                elif event_action == 'expiration':
                    self.expiration = event_date
        except:
            pass

        # "WHOIS": {"secureDNS": {"delegationSigned": false}}
        try:
            self.dnssec = self.domain_whois['secureDNS']['delegationSigned']
        except:
            pass

        #  "WHOIS": {"nameservers": [["NS1.GOOGLE.COM", "216.239.32.10"], ["NS2.GOOGLE.COM", "216.239.34.10"]]}
        try:
            for nameserver in self.domain_whois['nameservers']:
                # print(nameserver['ldhName'])
                ns = nameserver['ldhName'].lower()
                # print(result)
                ip = get_a_record(ns)
                # print(ns, ip)
                self.whois_nameservers.append([ns, ip])
                self.whois_ns.append(ns)
        except:
            pass

    def get_domain_dns(self):
        try:
            res_ns = get_ns_records(self.domain)
            for ns in res_ns:
                ip = get_a_record(ns)
                self.ns.append(ns)
                self.domain_nameservers.append([ns, ip])
                if "cloudflare" in ns:
                    # print("Cloudflare: FullZone detected")
                    self.waf = 'Cloudflare: FullZone detected'
            self.dns_lookup_continue = True
        except:
            # No point in checking for DNS is there are no nameservers with IP's responding
            self.dns_lookup_continue = False
            pass

        if self.dns_lookup_continue or self.dns_lookup_force:
            try:
                # SOA query the host's DNS
                self.soa = get_soa_record(self.domain)
                if "cloudflare" in self.soa['nsname']:
                    self.waf = 'Cloudflare: FullZone detected'
            except:
                pass

            try:
                self.dkim = get_dkim_records(self.domain)
                for key in self.dkim:
                    self.domain_txt.append(['TXT', str(key), self.dkim[key]])
            except:
                pass

            try:
                self.dmarc = get_dmarc_record(self.domain)
                if self.dmarc is not None:
                    self.domain_txt.append(['TXT', str(f'_dmarc.{self.domain}'), str(self.dmarc)])
            except:
                pass

            try:
                # WWW query the host's DNS
                www_name = 'www.' + self.domain
                res_cname = get_cname_record(www_name)
                if res_cname is not None:
                    self.domain_www.append(['CNAME', str(www_name), str(res_cname)])
                    if "cloudflare" in res_cname:
                        self.waf = 'Cloudflare: CNAME detected'
                    if "quic.cloud" in res_cname:
                        self.waf = "QUIC.cloud CDN: CNAME detected"
            except:
                pass

            try:
                www_name = 'www.' + self.domain
                domain_www_a = get_a_record(www_name)
                if domain_www_a is not None:
                    self.domain_www.append(['A', str(www_name), str(domain_www_a)])
            except:
                pass

            try:
                domain_a = get_a_record(self.domain)
                if domain_a is not None:
                    self.domain_www.append(['A', str(self.domain), str(domain_a)])
            except:
                pass

            try:
                domain_aaaa = get_aaaa_record(self.domain)
                if domain_aaaa is not None:
                    self.domain_www.append(['AAAA', str(self.domain), str(domain_aaaa)])
            except:
                pass

            try:
                # MX query the host's DNS
                res_mx = get_mx_records(self.domain)
                for elem in res_mx:
                    self.domain_mx.append(['MX', str(elem.host), str(elem.priority)])
            except:
                pass

            try:
                res_txt = self.loop.run_until_complete(self.resolver.query(self.domain, 'TXT'))
                for elem in res_txt:
                    # print(str(elem.text))
                    self.domain_txt.append(['TXT', str(self.domain), str(elem.text)])
                    if 'v=spf' in str(elem.text):
                        self.spf = str(elem.text)
            except:
                pass

            domain_dict = {
                'domain': self.domain,
                'rdapurl': self.rdap_url,
                'WHOIS': {
                    'Registrar': self.registrar,
                    'registration': self.registration,
                    'expiration': self.expiration,
                    'secureDNS': self.dnssec,
                    'status': self.whois_statuses,
                    'nameservers': self.whois_nameservers,

                },
                'DNS': {
                    'SOA': self.soa['SOA'],
                    'NS': self.domain_nameservers,
                    'WWW': self.domain_www,
                    'MX': self.domain_mx,
                    'TXT': self.domain_txt,
                }
            }

            print(domain_dict)
            self.domain_dict = domain_dict

    def get_whois_domain(self):
        self.domain_whois = get_domain_rdap_info(self.domain)
        if self.domain_whois:
            self.create_domain_dict_rdap()
        else:
            self.rdap_url = 'NA'
            self.get_domain_whois_info()

    def check_auth_nameservers_match(self):
        if sorted(self.whois_ns) == sorted(self.ns):
            # print('Authoritative NS and DNS nameservers match')
            self.auth_ns_match = True
        else:
            self.auth_ns_match = False


# How to use
def check_domaininfo():
    domain = DomainInfo('wizardassistant.com')
    print(f"{domain.domain}'s is expired {domain.expired} ")
    print(f"{domain.domain}'s registrar is {domain.registrar} ")
    print(f"Whois Nameservers: {domain.whois_nameservers} ")
    print(f"{domain.domain}'s registrar status: {domain.status}")
    # print(type(domain.status))
    print(f"Domain's WAF/CDN Status: {domain.waf}")
    print(f"Domain's DNSSEC Status: {domain.dnssec}")
    print(f"WWW records: {domain.domain_www}")
    print(f"SOA record: {domain.soa}")
    print(f"MX records: {domain.domain_mx}")
    print(f"DNS Nameservers: {domain.ns} ")
    print(f"Domain's SPF: {domain.spf} ")
    print(f"Domain's DKIM: {domain.dkim} ")
    print(f"Domain's DMARC: {domain.dmarc} ")
    print(f"Domain Expiration: {domain.expiration} ")
    print(f"Whois Nameservers: {domain.whois_ns} ")
    print(f"DNS Nameservers: {domain.ns} ")
    print(f"Auth WHOIS and DNS Nameservers match: {domain.auth_ns_match} ")
    print(f"WAF check: {domain.waf} ")
    # for key, value in domain.dns.items():
    #    print(key, ':', value)
    print(json.dumps(domain.domain_dict, indent=4, sort_keys=False))


# elapsed_time = timeit.timeit(check_domaininfo, number=1)/1
# print("DNS Lookup took: ", elapsed_time)

# check_domaininfo()

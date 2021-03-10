"""Tests for the `utils` module."""

from wizard_domaininfo import utils


def test_check_http_reachable():
    """Basic HTTP test."""
    assert utils.check_http_reachable("google.com"), "Should be True as Google is always online."
    assert utils.check_http_reachable("https://google.com"), "Should be True as Google is always online."


def test_check_http_reachable_false():
    """Basic HTTP test."""
    assert not utils.check_http_reachable("google"), "Should be False as google is not a valid domain."


def test_check_url_ssl():
    """Basic HTTPS test."""
    assert utils.check_url_ssl("google.com"), "Should be True as Google is always online and has SSL"


def test_check_url_ssl_false():
    """Basic HTTPS test false."""
    assert not (utils.check_url_ssl("https://expired.badssl.com/")), "Should be False as this is a known expired SSL."


def test_get_rdns_from_ip():
    """Basic get RDNS via PTR lookup"""
    assert utils.get_rdns_from_ip("8.8.8.8") == "dns.google", "Should return dns.google as this is the correct value"
    assert not utils.get_rdns_from_ip("8.8.8.8") == "one.one.one.one", "Should not return one.one.one.one"
    assert utils.get_rdns_from_ip("9999.999.999.9999") == "", "Should return empty string"


def test_get_hostname_from_ip():
    """Basic get RDNS via gethostbyaddr"""
    assert utils.get_hostname_from_ip("1.1.1.1") == "one.one.one.one", "Should return one.one.one.one"
    assert not utils.get_hostname_from_ip("1.1.1.1") == "dns.google", "Should not return dns.google"
    assert utils.get_hostname_from_ip("9999.999.999.9999") == "", "Should return empty string"


def test_get_domain_whois_info_legacy():
    assert utils.get_domain_whois_info_legacy("google.com.au"), "Should return True"
    assert not utils.get_domain_whois_info_legacy("google.invalid"), "Should return False"


def test_get_domain_whois_expiration_date_legacy():
    assert (
        utils.get_domain_whois_expiration_date_legacy("google.com") == "2028-09-14 04:00:00"
    ), "Should return 2028-09-14 04:00:00"
    assert not utils.get_domain_whois_expiration_date_legacy("google.invalid"), "Should return False"


def test_get_domain_rdap_info():
    assert utils.get_domain_rdap_info("google.com")["ldhName"] == "GOOGLE.COM", "Should return GOOGLE.COM"
    assert not utils.get_domain_rdap_info("facebook"), "Should return False as not valid domain"


def test_get_domain_whois_event_date_rdap():
    assert (
        utils.get_domain_whois_event_date_rdap("google.com", "registration") == "1997-09-15 04:00:00"
    ), "Should Return: 1997-09-15 04:00:00"
    assert not utils.get_domain_whois_event_date_rdap("google.invalid", "registration"), "Should Return: False"


def test_get_domain_whois_expiration_date_rdap():
    assert (
        utils.get_domain_whois_expiration_date_rdap("google.com") == "2028-09-14 04:00:00"
    ), "Should return 2028-09-14 04:00:00"


def test_get_domain_whois_registration_date_rdap():
    assert (
        utils.get_domain_whois_registration_date_rdap("google.com") == "1997-09-15 04:00:00"
    ), "Should Return: 1997-09-15 04:00:00"

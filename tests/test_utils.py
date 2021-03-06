"""Tests for the `utils` module."""

import pytest

from wizard_domaininfo import utils


def test_check_http_reachable():
    """Basic HTTP test."""
    assert utils.check_http_reachable("google.com") == True, "Should be True as Google is always online."


def test_check_http_reachable_false():
    """Basic HTTP test."""
    assert utils.check_http_reachable("google") == False, "Should be False as google is not a valid domain."


def test_check_url_ssl():
    """Basic HTTPS test."""
    assert utils.check_url_ssl("google.com") == True, "Should be True as Google is always online and has SSL"


def test_check_url_ssl_false():
    """Basic HTTPS test false."""
    assert (
        utils.check_url_ssl("https://expired.badssl.com/") == False
    ), "Should be False as this is a known expired SSL."

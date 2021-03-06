import requests
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


# wizard_whois.net.socket.setdefaulttimeout(TIMEOUT)


def check_http_reachable(domain_name):
    """Check if the domain is reachable via http.

    Args:
        domain_name (): domain_name Domain name to check is reachable.

    Returns:
        Boolean

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

    Args:
        domain_name (): domain_name Domain name to check SSL for.

    Returns:
        Boolean

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

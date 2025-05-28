import requests
from urllib3.exceptions import InsecureRequestWarning
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# Disable SSL verification warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=ssl.PROTOCOL_TLSv1_2,
            ssl_context=ctx
        )

def create_session():
    session = requests.Session()
    adapter = TLSAdapter()
    session.mount("https://", adapter)
    session.verify = False
    return session

def make_request(url, method="GET", **kwargs):
    session = create_session()
    try:
        response = session.request(method, url, timeout=30, **kwargs)
        return response
    except requests.exceptions.SSLError:
        # Retry with SSL verification disabled
        kwargs['verify'] = False
        return session.request(method, url, timeout=30, **kwargs)
    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed for {url}: {str(e)}")
        return None
    finally:
        session.close() 
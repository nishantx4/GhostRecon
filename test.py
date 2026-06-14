import requests
import urllib3
urllib3.disable_warnings()

try:
    r = requests.get('https://pentest-ground.com:7001', verify=False, timeout=10, allow_redirects=True)
    print(f'Status: {r.status_code}')
    print(f'Final URL: {r.url}')
    print('History:')
    for h in r.history:
        print(f'  {h.status_code} -> {h.headers.get("Location")}')
except Exception as e:
    print(e)

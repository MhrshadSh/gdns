import requests
import json
from requests.auth import HTTPBasicAuth

login_url = 'https://api.watttime.org/login'
rsp = requests.get(login_url, auth=HTTPBasicAuth('mehrshad', 'Meh@06022000'))
TOKEN = rsp.json()['token']
print(rsp.json())



url = "https://api.watttime.org/v3/maps"

headers = {"Authorization": f"Bearer {TOKEN}"}
params = {"signal_type": "co2_moer"}

response = requests.get(url, headers=headers, params=params)
response.raise_for_status()

geojson_data = response.json()

# Save locally for reuse (recommended)
with open("watttime_regions.geojson", "w") as f:
    json.dump(geojson_data, f)

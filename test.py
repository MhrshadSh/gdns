import sys
import csv
from datetime import timedelta
from typing import Optional
from dataclasses import dataclass
from scamper import ScamperCtrl, ScamperFile
from collections import defaultdict
import ipinfo
import requests
from requests.auth import HTTPBasicAuth

access_token = '6259fe15f8d92f'
handler = ipinfo.getHandler(access_token)
DNS_TIMEOUT = 10  # seconds
PING_TIMEOUT = 10  # seconds
TRACEROUTE_TIMEOUT = 300  # seconds
domain = "tiktok.com"
resolver = "8.8.8.8"


login_url = 'https://api.watttime.org/login'
access_url = "https://api.watttime.org/v3/my-access"
region_url = "https://api.watttime.org/v3/region-from-loc"
forecast_url = "https://api.watttime.org/v3/forecast"
df_historical_url = "https://api.watttime.org/v3/historical"
current_url = "https://api.watttime.org/v3/signal-index"


@dataclass
class MeasurementRecord:
    """Structured tuple emitted to the mux + downstream consumers."""

    node: str
    domain: str
    resolver: str
    timestamp: str
    dest_ip: Optional[str] = None 
    rtt_ms: Optional[float] = None
    hop_count: Optional[int] = None
    carbon_intensity: Optional[float] = None


def get_wt_region(latitude, longitude, token, signal_type="co2_moer"):
    headers = {"Authorization": f"Bearer {token}"}
    params = {"latitude": str(latitude), "longitude": str(longitude), "signal_type": signal_type}
    response = requests.get(region_url, headers=headers, params=params)
    response.raise_for_status()
    region = response.json()['region']
    return region

def get_current_ci(latitude, longitude, token, signal_type="co2_moer"):
    region = get_wt_region(latitude, longitude, token, signal_type=signal_type)

    headers = {"Authorization": f"Bearer {token}"}
    params = {
        "region": region,
        "signal_type": signal_type,
    }
    response = requests.get(current_url, headers=headers, params=params)
    response.raise_for_status()
    current = response.json()['data'][0]
    return current['value']


def export_results_to_csv(ip_results, filename="results.csv"):
    """Export measurement results to CSV with column headers."""
    rows = []
    for vp, ips_dict in ip_results.items():
        vp_name = vp.name if hasattr(vp, 'name') else str(vp)
        for ip, metrics in ips_dict.items():
            rows.append({
                'vp': vp_name,
                'dest': str(ip),
                'version': 'IPv6' if ip.is_ipv6() else 'IPv4',
                'avg_rtt_ms': metrics.get('avg_rtt_ms'),
                'min_rtt_ms': metrics.get('min_rtt_ms'),
                'stddev_rtt_ms': metrics.get('stddev_rtt_ms'),
                'hop_count': metrics.get('hop_count', None),
                'co2_moer': metrics.get('co2_moer', None)
            })
    
    if rows:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['vp', 'dest', 'version', 'avg_rtt_ms', 'min_rtt_ms', 'stddev_rtt_ms', 'hop_count', 'co2_moer'])
            writer.writeheader()
            writer.writerows(rows)
        print(f"Results saved to {filename}")
    else:
        print("No results to export")


def measure_vp(mux_path, target, output_file="/home/gdns/gdns/results.warts", server=None):
    outfile = ScamperFile(filename=output_file, mode='w')
    ctrl = ScamperCtrl(mux=mux_path, outfile=outfile)
    # Select only DNS-capable vantage points
    vps = [vp for vp in ctrl.vps() if 'primitive:dns' in vp.tags]
    vp_lookup = {vp.name: vp for vp in vps} 
    print(f"Total DNS-capable VPs: {len(vps)}")
    # vps = vps[:2]  # Limit to first n VPs for testing
    ctrl.add_vps(vps)

    # 1. DNS A records
    print(f"Resolving {target} A records...")
    for i in ctrl.instances():
        ctrl.do_dns(target, qtype='A', inst=i, server=server)
    
    # Collect DNS results
    print("Collecting DNS A results...")
    dns_results = defaultdict(list)
    for o in ctrl.responses(timeout=timedelta(seconds=DNS_TIMEOUT)):
        dns_results[o.inst].extend(o.ans_addrs())
    
    print(f"Resolving {target} AAAA records...") ####### should be merged with above --------------- v4 and v6 together
    for i in ctrl.instances():
        if 'network:ipv6' in vp_lookup[i.name].tags:
            ctrl.do_dns(target, qtype='AAAA', inst=i, server=server)
    
    # Collect DNS AAAA results
    print("Collecting DNS AAAA results...")
    for o in ctrl.responses(timeout=timedelta(seconds=DNS_TIMEOUT)):
        dns_results[o.inst].extend(o.ans_addrs())

    print("scheduling ping Measurements to resolved IPs...")
    for vp, addrs in dns_results.items():
        for ip in addrs:
            ctrl.do_ping(ip, inst=vp)

    # Collect ping results
    print("Collecting ping results...")
    ip_results = defaultdict(lambda: defaultdict(dict))
    for o in ctrl.responses(timeout=timedelta(seconds=PING_TIMEOUT)):
        ip_results[o.inst][o.dst]['avg_rtt_ms'] = (o.avg_rtt.total_seconds()*1000 if o.avg_rtt else None)
        ip_results[o.inst][o.dst]['min_rtt_ms'] = (o.min_rtt.total_seconds()*1000 if o.min_rtt else None)
        ip_results[o.inst][o.dst]['stddev_rtt_ms'] = (o.stddev_rtt.total_seconds()*1000 if o.stddev_rtt else None)
    
    print("Adding carbon intensity data to resolved IPs...")
    # To login to wattime and obtain an access token, use this code:
    rsp = requests.get(login_url, auth=HTTPBasicAuth('mehrshad', 'Meh@06022000'))
    TOKEN = rsp.json()['token']

    # add carbon intensity data
    for vp, ips in ip_results.items():
        for ip in ips:
            try:
                details = handler.getDetails(str(ip))
                latitude, longitude = details.latitude, details.longitude
                ci = get_current_ci(latitude, longitude, TOKEN, signal_type="co2_moer")
                ip_results[vp][ip]['co2_moer'] = ci
            except Exception as e:
                ip_results[vp][ip]['co2_moer'] = None

    print("scheduling traceroute Measurements to resolved IPs...")
    # traceroute to each resolved IP
    for vp, addrs in dns_results.items():
        for ip in addrs:
            ctrl.do_trace(ip, inst=vp)

    print("Collecting traceroute results...")
    for o in ctrl.responses(timeout=timedelta(seconds=60)):
        ip_results[o.inst][o.dst]['hop_count'] = (o.hop_count if o.hop_count else None)
    
    
    # print results
    print("All candidates latencies and hop counts:")
    for vp, l in ip_results.items():
        print(f"From VP: {vp.name}")
        for ip, metrics in l.items():
            rtt_ms = metrics.get('avg_rtt_ms')
            hop_count = metrics.get('hop_count')
            print(f"\t{ip:20} RTT: {rtt_ms} ms, Hops: {hop_count}")

    # Export results to CSV
    export_results_to_csv(ip_results, filename=output_file.replace('.warts', '.csv'))

    # Clean up
    outfile.close()
    ctrl.done()

if __name__ == "__main__":
    # if len(sys.argv) != 3:
    #     print("Usage: python script.py <mux_socket_path> <target_host>")
    #     sys.exit(1)
    # measure_vp(sys.argv[1], target=sys.argv[2])
    measure_vp("/run/ark/mux", target=domain)

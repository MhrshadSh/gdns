import sys
import csv
from datetime import timedelta, timezone, datetime
from typing import Optional
from dataclasses import dataclass
from scamper import ScamperCtrl, ScamperFile, ScamperTrace, ScamperHost
from collections import defaultdict
import ipinfo
import requests
from requests.auth import HTTPBasicAuth


DNS_TIMEOUT = 10  # seconds
PING_TIMEOUT = 10  # seconds
TRACEROUTE_TIMEOUT = 60  # seconds
EM_TOKEN = "ptTcw6cZ9zS07WgBYgXP"
IPINFO_TOKEN = '6259fe15f8d92f'
handler = ipinfo.getHandler(IPINFO_TOKEN)
domain = "www.youtube.com"
resolvers = ["local", "1.1.1.1", "9.9.9.9", "45.90.28.207"]


login_url = 'https://api.watttime.org/login'
access_url = "https://api.watttime.org/v3/my-access"
region_url = "https://api.watttime.org/v3/region-from-loc"
forecast_url = "https://api.watttime.org/v3/forecast"
df_historical_url = "https://api.watttime.org/v3/historical"
current_url = "https://api.watttime.org/v3/signal-index"
em_latest_url = "https://api.electricitymaps.com/v3/carbon-intensity/latest"

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
    """Get the WattTime region for a given latitude and longitude.
    """
    headers = {"Authorization": f"Bearer {token}"}
    params = {"latitude": str(latitude), "longitude": str(longitude), "signal_type": signal_type}
    response = requests.get(region_url, headers=headers, params=params)
    response.raise_for_status()
    region = response.json()['region']
    return region


def fetch_signal(latitude, longitude, token, signal_type="co2_moer", offset_hours=1):
    """
    Fetch the most recent historical signal data for a given location and time offset.
    Returns a list of signal values for the specified offset hours.
    """

    if signal_type=="co2_moer":
        region = get_wt_region(latitude, longitude, token, signal_type=signal_type)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        start_time = (now - timedelta(hours=offset_hours)).isoformat()
        end_time = now.isoformat()

        headers = {"Authorization": f"Bearer {token}"}
        params = {
            "region": region,
            "start": start_time,
            "end": end_time,
            "signal_type": signal_type,
        }
        response = requests.get(df_historical_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get('data', [])
        # Return the list of 'value' entries when present, otherwise return None
        values = [item['value'] if isinstance(item, dict) and 'value' in item else None for item in data]
        return values
    
    elif signal_type=="co2_aoer":
        url = f"{em_latest_url}?lat={latitude}&lon={longitude}&emissionFactorType=direct"
        response = requests.get(
            url,
            headers={
                "auth-token": EM_TOKEN
            }
        )
        return response.json()["carbonIntensity"]
        



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
                'resolver': metrics.get('resolver', None),
                'avg_rtt_ms': metrics.get('avg_rtt_ms'),
                'min_rtt_ms': metrics.get('min_rtt_ms'),
                'stddev_rtt_ms': metrics.get('stddev_rtt_ms'),
                'hop_count': metrics.get('hop_count', None),
                'co2_moer': metrics.get('co2_moer', None),
                'co2_aoer': metrics.get('co2_aoer', None),
            })
    
    if rows:
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['vp', 'dest', 'version', 'resolver', 'avg_rtt_ms', 'min_rtt_ms', 'stddev_rtt_ms', 'hop_count', 'co2_moer', 'co2_aoer'])
            writer.writeheader()
            writer.writerows(rows)
        print(f"Results saved to {filename}")
    else:
        print("No results to export")


def measure_vp(mux_path, target, output_file="/home/gdns/gdns/results.warts", resolvers: list=["local"]):
    outfile = ScamperFile(filename=output_file, mode='w')
    ctrl = ScamperCtrl(mux=mux_path, outfile=outfile)
    # Select only DNS-capable vantage points
    vps = [vp for vp in ctrl.vps() if 'primitive:dns' in vp.tags]
    vp_lookup = {vp.name: vp for vp in vps} 
    print(f"Total DNS-capable VPs: {len(vps)}")
    # vps = vps[:2]  # Limit to first n VPs for testing
    ctrl.add_vps(vps)
    dns_results = defaultdict(set)  # vp -> set of resolved IPs
    resolver_results = defaultdict(lambda: defaultdict(set))  # vp -> resolver -> set of resolved IPs
    ip_results = defaultdict(lambda: defaultdict(dict))  # vp -> ip -> metrics dict

    # To login to wattime and obtain an access token, use this code:
    try:
        rsp = requests.get(login_url, auth=HTTPBasicAuth('mehrshad', 'Meh@06022000'))
        WT_TOKEN = rsp.json()['token']
    except Exception as e:
        print(f"Error logging into WattTime: {e}")
        WT_TOKEN = None

    for resolver in resolvers:
        if resolver == "local":
            resolver = None  # Use local resolver
        # 1. DNS A records
        print(f"Resolving {target} A/AAAA records via ({resolver or 'local resolver'})...")
        for i in ctrl.instances():
            ctrl.do_dns(target, qtype='A', inst=i, server=resolver)
            if 'network:ipv6' in vp_lookup[i.name].tags:
                ctrl.do_dns(target, qtype='AAAA', inst=i, server=resolver)
        
        # Collect DNS results
        print("Collecting DNS A/AAAA results...")
        rrsets_to_ping = defaultdict(set)  # vp -> set of IPs, to be pinged. To avoid pinging duplicates
        for o in ctrl.responses(timeout=timedelta(seconds=DNS_TIMEOUT)):
            if not isinstance(o, ScamperHost):
                continue  # skip non-DNS responses 
            ans = set(o.ans_addrs() or [])
            new_addrs = ans - dns_results[o.inst]
            if new_addrs:
                rrsets_to_ping[o.inst].update(new_addrs)
                dns_results[o.inst].update(new_addrs)
                resolver_results[o.inst][resolver or 'local'].update(ans)
        

        print("scheduling ping Measurements to resolved IPs...")
        for vp, addrs in rrsets_to_ping.items():
            for ip in addrs:
                ctrl.do_ping(ip, inst=vp)

        # Collect ping results
        print("Collecting ping results...")
        
        for o in ctrl.responses(timeout=timedelta(seconds=PING_TIMEOUT)):
            ip_results[o.inst][o.dst]['avg_rtt_ms'] = (o.avg_rtt.total_seconds()*1000 if o.avg_rtt else None)
            ip_results[o.inst][o.dst]['min_rtt_ms'] = (o.min_rtt.total_seconds()*1000 if o.min_rtt else None)
            ip_results[o.inst][o.dst]['stddev_rtt_ms'] = (o.stddev_rtt.total_seconds()*1000 if o.stddev_rtt else None)
            ip_results[o.inst][o.dst]['resolver'] = resolver or 'local'

        print("scheduling traceroute Measurements to resolved IPs...")
        # traceroute to each resolved IP
        for vp, addrs in dns_results.items():
            for ip in addrs:
                ctrl.do_trace(ip, inst=vp)

        
        print("Adding carbon intensity data to resolved IPs...")
        # add carbon intensity data
        for vp, ips in ip_results.items():
            for ip in ips:
                try:
                    details = handler.getDetails(str(ip))
                    latitude, longitude = details.latitude, details.longitude
                    
                    # fetch recent co2_moer values
                    moer_list_recent = fetch_signal(latitude, longitude, WT_TOKEN, signal_type="co2_moer", offset_hours=1)
                    # pick the most recent non-None value
                    moer = None
                    if moer_list_recent:
                        for val in reversed(moer_list_recent):
                            if val is not None:
                                moer = val
                                break
                    ip_results[vp][ip]['co2_moer'] = moer
                except Exception as e:
                    ip_results[vp][ip]['co2_moer'] = None
                    print(f"Error fetching moer for IP {ip}: {e}")

                try:
                    # fetch co2_aoer value
                    aoer = fetch_signal(latitude, longitude, EM_TOKEN, signal_type="co2_aoer")
                    ip_results[vp][ip]['co2_aoer'] = aoer
                except Exception as e:
                    ip_results[vp][ip]['co2_aoer'] = None
                    print(f"Error fetching aoer for IP {ip}: {e}")
        
        print("Collecting traceroute results...")
        for o in ctrl.responses(timeout=timedelta(seconds=TRACEROUTE_TIMEOUT)):
            if not isinstance(o, ScamperTrace):
                continue  # skip non-traceroute responses
            ip_results[o.inst][o.dst]['hop_count'] = (o.hop_count if o.hop_count else None)

        for e in ctrl.exceptions():
            print(f"Error during measurements: {e}")

    

        
    # print results
    # print("All candidates latencies and hop counts:")
    # for vp, l in ip_results.items():
    #     print(f"From VP: {vp.name}")
    #     for ip, metrics in l.items():
    #         rtt_ms = metrics.get('avg_rtt_ms')
    #         hop_count = metrics.get('hop_count')
    #         print(f"\t{ip:20} RTT: {rtt_ms} ms, Hops: {hop_count}")

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
    measure_vp("/run/ark/mux", target=domain, resolvers=resolvers)

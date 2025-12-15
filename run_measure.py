import sys
import csv
import os
import time
from datetime import timedelta, timezone, datetime
from typing import Optional, Dict
from dataclasses import dataclass
from scamper import ScamperCtrl, ScamperFile, ScamperTrace, ScamperHost, ScamperPing
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
resolvers = ["local", "1.1.1.1"]


login_url = 'https://api.watttime.org/login'
access_url = "https://api.watttime.org/v3/my-access"
region_url = "https://api.watttime.org/v3/region-from-loc"
forecast_url = "https://api.watttime.org/v3/forecast"
df_historical_url = "https://api.watttime.org/v3/historical"
current_url = "https://api.watttime.org/v3/signal-index"
em_latest_url = "https://api.electricitymaps.com/v3/carbon-intensity/latest"


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
        

@dataclass
class IPMeasurement:
    dest: str
    version: str
    resolver: str
    cycle_start_iso: Optional[str] = None
    avg_rtt_ms: Optional[float] = None
    min_rtt_ms: Optional[float] = None
    stddev_rtt_ms: Optional[float] = None
    hop_count: Optional[int] = None
    country: Optional[str] = None
    co2_moer: Optional[float] = None
    co2_aoer: Optional[float] = None


def _ensure_measurement(ip_results: Dict[str, Dict[str, IPMeasurement]], vp_name, ip, resolver, cycle_start_iso) -> IPMeasurement:
    """
    Ensure we have a measurement object for a vp/ip pair. This keeps all metrics in one place.
    """
    dest = str(ip)
    measurement = ip_results[vp_name].get(dest)
    if measurement is None:
        version = 'IPv6' if getattr(ip, "is_ipv6", lambda: False)() else 'IPv4'
        measurement = IPMeasurement(dest=dest, version=version, resolver=resolver or 'local', cycle_start_iso=cycle_start_iso)
        ip_results[vp_name][dest] = measurement
    else:
        if not measurement.resolver:
            measurement.resolver = resolver or 'local'
        if measurement.cycle_start_iso is None:
            measurement.cycle_start_iso = cycle_start_iso
    return measurement


def export_results_to_csv(ip_results, filename="results.csv", append: bool = False):
    """Export measurement results to CSV with column headers."""
    rows = []
    for vp_name, ips_dict in ip_results.items():
        for measurement in ips_dict.values():
            rows.append({
                'vp': vp_name,
                'dest': measurement.dest,
                'version': measurement.version,
                'resolver': measurement.resolver,
                'cycle_start_iso': measurement.cycle_start_iso,
                'avg_rtt_ms': measurement.avg_rtt_ms,
                'min_rtt_ms': measurement.min_rtt_ms,
                'stddev_rtt_ms': measurement.stddev_rtt_ms,
                'hop_count': measurement.hop_count,
                'co2_moer': measurement.co2_moer,
                'co2_aoer': measurement.co2_aoer,
            })
    
    if rows:
        fieldnames = ['vp', 'dest', 'version', 'resolver', 'cycle_start_iso', 'avg_rtt_ms', 'min_rtt_ms', 'stddev_rtt_ms', 'hop_count', 'co2_moer', 'co2_aoer']
        mode = 'a' if append and os.path.exists(filename) else 'w'
        write_header = not (append and os.path.exists(filename))
        with open(filename, mode, newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            writer.writerows(rows)
        print(f"Results saved to {filename}")
    else:
        print("No results to export")


def measure_vp(mux_path, target, output_file="/home/gdns/gdns/results.warts", resolvers: list=["local"], cycle_start_iso: Optional[str] = None, append_csv: bool = False):
    outfile = ScamperFile(filename=output_file, mode='w')
    ctrl = ScamperCtrl(mux=mux_path, outfile=outfile)
    # Select only DNS-capable vantage points
    vps = [vp for vp in ctrl.vps() if 'primitive:dns' in vp.tags]
    vp_lookup = {vp.name: vp for vp in vps} 
    print(f"Total DNS-capable VPs: {len(vps)}")
    vps = vps[:2]  # Limit to first n VPs for testing
    ctrl.add_vps(vps)
    dns_results = defaultdict(set)  # vp -> set of resolved IPs
    resolver_results = defaultdict(lambda: defaultdict(set))  # vp -> resolver -> set of resolved IPs
    ip_results: Dict[str, Dict[str, IPMeasurement]] = defaultdict(dict)  # vp -> ip -> measurement dataclass
    carbon_cache: Dict[str, Dict[str, Optional[float]]] = {}  # per-cycle cache to avoid duplicate carbon lookups
    global_gip = []  # list of tuples (int, str) ordered by first element
    

    

    for resolver in resolvers:

        # login to wattime and obtain an access token ====================== Must be done less than every 30 minutes to avoid token expiration
        try:
            rsp = requests.get(login_url, auth=HTTPBasicAuth('mehrshad', 'Meh@06022000'))
            WT_TOKEN = rsp.json()['token']
        except Exception as e:
            print(f"Error logging into WattTime: {e}")
            WT_TOKEN = None

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
            if not isinstance(o, ScamperPing):
                continue  # skip non-ping responses
            vp_name = o.inst.name if hasattr(o.inst, 'name') else str(o.inst)
            measurement = _ensure_measurement(ip_results, vp_name, o.dst, resolver, cycle_start_iso)
            measurement.avg_rtt_ms = (o.avg_rtt.total_seconds()*1000 if o.avg_rtt else None)
            measurement.min_rtt_ms = (o.min_rtt.total_seconds()*1000 if o.min_rtt else None)
            measurement.stddev_rtt_ms = (o.stddev_rtt.total_seconds()*1000 if o.stddev_rtt else None)
            measurement.resolver = resolver or 'local'

        print("scheduling traceroute Measurements to resolved IPs...")
        # traceroute to each resolved IP
        for vp, addrs in dns_results.items():
            for ip in addrs:
                ctrl.do_trace(ip, inst=vp)

        
        print("Adding carbon intensity data to resolved IPs...")
        # add carbon intensity data
        for _vp_name, ips in ip_results.items():
            for ip_str, measurement in ips.items():
                # Skip duplicate lookups within the same cycle by using a simple cache keyed by IP string
                cache_entry = carbon_cache.get(ip_str)
                if cache_entry:
                    measurement.country = cache_entry.get("country")
                    measurement.co2_moer = cache_entry.get("co2_moer")
                    measurement.co2_aoer = cache_entry.get("co2_aoer")
                    continue

                country_val = None
                moer_val = measurement.co2_moer
                aoer_val = measurement.co2_aoer

                try:
                    details = handler.getDetails(ip_str)
                    latitude, longitude = details.latitude, details.longitude
                    country_val = details.country
                    measurement.country = country_val

                    # fetch recent co2_moer values if not already present
                    if moer_val is None:
                        moer_list_recent = fetch_signal(latitude, longitude, WT_TOKEN, signal_type="co2_moer", offset_hours=1)
                        moer = None
                        if moer_list_recent:
                            for val in reversed(moer_list_recent):
                                if val is not None:
                                    moer = val
                                    break
                        moer_val = moer
                        measurement.co2_moer = moer_val

                except Exception as e:
                    measurement.co2_moer = None
                    print(f"Error fetching moer for IP {ip_str}: {e}")

                try:
                    # fetch co2_aoer value if not already present
                    if aoer_val is None:
                        aoer_val = fetch_signal(latitude, longitude, EM_TOKEN, signal_type="co2_aoer")
                        measurement.co2_aoer = aoer_val

                except Exception as e:
                    measurement.co2_aoer = None
                    print(f"Error fetching aoer for IP {ip_str}: {e}")

                carbon_cache[ip_str] = {
                    "country": country_val,
                    "co2_moer": moer_val,
                    "co2_aoer": aoer_val,
                }
        
        print("Collecting traceroute results...")
        for o in ctrl.responses(timeout=timedelta(seconds=TRACEROUTE_TIMEOUT)):
            if not isinstance(o, ScamperTrace):
                continue  # skip non-traceroute responses
            vp_name = o.inst.name if hasattr(o.inst, 'name') else str(o.inst)
            measurement = _ensure_measurement(ip_results, vp_name, o.dst, resolver, cycle_start_iso)
            measurement.hop_count = (o.hop_count if o.hop_count else None)

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
    export_results_to_csv(ip_results, filename=output_file.replace('.warts', '.csv'), append=append_csv)

    # Clean up
    outfile.close()
    ctrl.done()
    

def run_cycles(mux_path, target, output_file, resolvers, interval_minutes: int, cycles: int):
    """
    Run measurements every interval_minutes for a fixed number of cycles.
    Each cycle uses the planned start time as its timestamp; if a cycle runs long,
    the next one still starts at its scheduled time (or immediately if behind).
    """
    first_start = datetime.now(timezone.utc).replace(microsecond=0)
    for i in range(cycles):
        cycle_start = first_start + timedelta(minutes=interval_minutes * i)
        now = datetime.now(timezone.utc)
        if now < cycle_start:
            sleep_seconds = (cycle_start - now).total_seconds()
            print(f"Waiting {sleep_seconds:.1f}s for next cycle start at {cycle_start.isoformat()}")
            time.sleep(sleep_seconds)
        planned_start_iso = cycle_start.isoformat()
        print(f"Starting cycle {i+1}/{cycles} at {planned_start_iso}")
        measure_vp(mux_path, target, output_file=output_file, resolvers=resolvers, cycle_start_iso=planned_start_iso, append_csv=True)


if __name__ == "__main__":
    # Example: run every 10 minutes for 3 cycles
    run_cycles("/run/ark/mux", target=domain, output_file="/home/gdns/gdns/results.warts", resolvers=resolvers, interval_minutes=10, cycles=3)

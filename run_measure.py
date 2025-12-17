import sys
import csv
import os
import time
import json
from datetime import timedelta, timezone, datetime
from typing import Optional, Dict
from dataclasses import dataclass
from scamper import ScamperCtrl, ScamperFile, ScamperTrace, ScamperHost, ScamperPing
from collections import defaultdict
import ipinfo
import requests
from requests.auth import HTTPBasicAuth


CONFIG_PATH = "/home/gdns/gdns/config.json"
IP_GEO_CACHE_PATH = "/home/gdns/gdns/ip_geo_cache.json"

# defaults used if config is absent; overridden on each cycle
DEFAULT_CONFIG = {
    "dns_timeout": 10,
    "ping_timeout": 10,
    "traceroute_timeout": 60,
    "em_token": "ptTcw6cZ9zS07WgBYgXP",
    "ipinfo_token": "6259fe15f8d92f",
    "domain": "www.youtube.com",
    "resolvers": ["local", "1.1.1.1"],
    "login_url": "https://api.watttime.org/login",
    "access_url": "https://api.watttime.org/v3/my-access",
    "region_url": "https://api.watttime.org/v3/region-from-loc",
    "forecast_url": "https://api.watttime.org/v3/forecast",
    "df_historical_url": "https://api.watttime.org/v3/historical",
    "current_url": "https://api.watttime.org/v3/signal-index",
    "em_latest_url": "https://api.electricitymaps.com/v3/carbon-intensity/latest",
    "limit_vps": None,
    "output_file": "/home/gdns/gdns/results/results.warts",
    "interval_minutes": 10,
    "cycles": 3,
    "green_list_size": 5,
    "carbon_basis": "moer",  # choose between "moer" or "aoer"
}

# runtime globals set via config
DNS_TIMEOUT = DEFAULT_CONFIG["dns_timeout"]
PING_TIMEOUT = DEFAULT_CONFIG["ping_timeout"]
TRACEROUTE_TIMEOUT = DEFAULT_CONFIG["traceroute_timeout"]
EM_TOKEN = DEFAULT_CONFIG["em_token"]
IPINFO_TOKEN = DEFAULT_CONFIG["ipinfo_token"]
handler = ipinfo.getHandler(IPINFO_TOKEN)
IP_GEO_CACHE: Dict[str, Dict[str, Optional[str]]] = {}  # persistent across whole execution
domain = DEFAULT_CONFIG["domain"]
resolvers = DEFAULT_CONFIG["resolvers"]
login_url = DEFAULT_CONFIG["login_url"]
access_url = DEFAULT_CONFIG["access_url"]
region_url = DEFAULT_CONFIG["region_url"]
forecast_url = DEFAULT_CONFIG["forecast_url"]
df_historical_url = DEFAULT_CONFIG["df_historical_url"]
current_url = DEFAULT_CONFIG["current_url"]
em_latest_url = DEFAULT_CONFIG["em_latest_url"]
limit_vps = DEFAULT_CONFIG["limit_vps"]
default_output_file = DEFAULT_CONFIG["output_file"]
default_interval_minutes = DEFAULT_CONFIG["interval_minutes"]
default_cycles = DEFAULT_CONFIG["cycles"]
green_list_size = DEFAULT_CONFIG["green_list_size"]
carbon_basis = DEFAULT_CONFIG["carbon_basis"]


def get_wt_region(latitude, longitude, token, signal_type="co2_moer"):
    """Get the WattTime region for a given latitude and longitude.
    """
    headers = {"Authorization": f"Bearer {token}"}
    params = {"latitude": str(latitude), "longitude": str(longitude), "signal_type": signal_type}
    response = requests.get(region_url, headers=headers, params=params)
    response.raise_for_status()
    region = response.json()['region']
    return region


def load_config(path: str = CONFIG_PATH) -> Dict:
    """Load config from JSON and overlay onto defaults; tolerant to missing file or keys."""
    cfg = DEFAULT_CONFIG.copy()
    try:
        with open(path, "r") as f:
            user_cfg = json.load(f)
            if isinstance(user_cfg, dict):
                cfg.update(user_cfg)
    except FileNotFoundError:
        print(f"Config file not found at {path}, using defaults.")
    except Exception as e:
        print(f"Error reading config at {path}, using defaults. Err: {e}")
    return cfg


def apply_config(cfg: Dict):
    """
    Apply config values to module-level settings so each cycle picks up changes.
    """
    global DNS_TIMEOUT, PING_TIMEOUT, TRACEROUTE_TIMEOUT
    global EM_TOKEN, IPINFO_TOKEN, handler, domain, resolvers
    global login_url, access_url, region_url, forecast_url, df_historical_url, current_url, em_latest_url
    global limit_vps, default_output_file, default_interval_minutes, default_cycles, green_list_size, carbon_basis

    DNS_TIMEOUT = cfg.get("dns_timeout", DNS_TIMEOUT)
    PING_TIMEOUT = cfg.get("ping_timeout", PING_TIMEOUT)
    TRACEROUTE_TIMEOUT = cfg.get("traceroute_timeout", TRACEROUTE_TIMEOUT)
    EM_TOKEN = cfg.get("em_token", EM_TOKEN)
    IPINFO_TOKEN = cfg.get("ipinfo_token", IPINFO_TOKEN)
    handler = ipinfo.getHandler(IPINFO_TOKEN)
    domain = cfg.get("domain", domain)
    resolvers = cfg.get("resolvers", resolvers)

    login_url = cfg.get("login_url", login_url)
    access_url = cfg.get("access_url", access_url)
    region_url = cfg.get("region_url", region_url)
    forecast_url = cfg.get("forecast_url", forecast_url)
    df_historical_url = cfg.get("df_historical_url", df_historical_url)
    current_url = cfg.get("current_url", current_url)
    em_latest_url = cfg.get("em_latest_url", em_latest_url)
    limit_vps = cfg.get("limit_vps", limit_vps)
    default_output_file = cfg.get("output_file", default_output_file)
    default_interval_minutes = cfg.get("interval_minutes", default_interval_minutes)
    default_cycles = cfg.get("cycles", default_cycles)
    green_list_size = cfg.get("green_list_size", green_list_size)
    carbon_basis = cfg.get("carbon_basis", carbon_basis)


def load_ip_geo_cache(path: str = IP_GEO_CACHE_PATH):
    """Load persistent IP geolocation cache from JSON, if present."""
    global IP_GEO_CACHE
    try:
        with open(path, "r") as f:
            data = json.load(f)
            if isinstance(data, dict):
                # Only accept dict-valued entries
                for ip, geo in data.items():
                    if isinstance(geo, dict):
                        IP_GEO_CACHE[ip] = geo
    except FileNotFoundError:
        # No cache yet, that's fine
        pass
    except Exception as e:
        print(f"Error reading IP geo cache at {path}: {e}")


def save_ip_geo_cache(path: str = IP_GEO_CACHE_PATH):
    """Persist current IP geolocation cache to JSON for next executions."""
    try:
        with open(path, "w") as f:
            json.dump(IP_GEO_CACHE, f)
    except Exception as e:
        print(f"Error writing IP geo cache to {path}: {e}")


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
    gip: Optional[bool] = False  # green IP flag


def _select_carbon_value(measurement: IPMeasurement, basis: str) -> Optional[float]:
    """
    Pick the carbon intensity to use for ranking based on the configured basis.
    Falls back to the other value if the preferred basis is missing.
    """
    basis_lower = (basis or "moer").lower()
    if basis_lower == "aoer":
        return measurement.co2_aoer if measurement.co2_aoer is not None else measurement.co2_moer
    # default to moer
    return measurement.co2_moer if measurement.co2_moer is not None else measurement.co2_aoer


def _update_green_list(green_list: list, ip: str, vp_name: str, resolver: str, carbon_value: float, max_size: int):
    """
    Maintain a fixed-size list of the greenest IPs (lowest carbon intensity).
    If the list exceeds max_size, drop the entry with the highest carbon value.
    """
    if carbon_value is None:
        return
    entry = (carbon_value, ip, vp_name, resolver or "local")

    # If IP already exists, keep the greener (lower) value
    for idx, item in enumerate(green_list):
        _, existing_ip, _, _ = item
        if existing_ip == ip:
            if carbon_value < item[0]:
                green_list[idx] = entry
            break
    else:
        green_list.append(entry)

    green_list.sort(key=lambda x: x[0])
    if len(green_list) > max_size:
        green_list.pop()  # remove the least green (largest carbon value)


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
                'dest_country': measurement.country,
                'avg_rtt_ms': measurement.avg_rtt_ms,
                'min_rtt_ms': measurement.min_rtt_ms,
                'stddev_rtt_ms': measurement.stddev_rtt_ms,
                'hop_count': measurement.hop_count,
                'co2_moer': measurement.co2_moer,
                'co2_aoer': measurement.co2_aoer,
                'gip': measurement.gip,
            })
    
    if rows:
        fieldnames = ['vp', 'dest', 'version', 'resolver', 'cycle_start_iso', 'dest_country', 'avg_rtt_ms', 'min_rtt_ms', 'stddev_rtt_ms', 'hop_count', 'co2_moer', 'co2_aoer', 'gip']
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
    if limit_vps is not None:
        vps = vps[:limit_vps]  # Limit to first n VPs for testing or per config
    ctrl.add_vps(vps)
    dns_results = defaultdict(set)  # vp -> set of resolved IPs
    resolver_results = defaultdict(lambda: defaultdict(set))  # vp -> resolver -> set of resolved IPs
    ip_results: Dict[str, Dict[str, IPMeasurement]] = defaultdict(dict)  # vp -> ip -> measurement dataclass
    carbon_cache: Dict[str, Dict[str, Optional[float]]] = {}  # per-cycle cache to avoid duplicate carbon lookups
    green_ip_list = []  # (carbon_value, ip, vp_name, resolver)

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
                else:
                    country_val = None
                    moer_val = measurement.co2_moer
                    aoer_val = measurement.co2_aoer

                    try:
                        geo = IP_GEO_CACHE.get(ip_str)
                        if geo is None:
                            details = handler.getDetails(ip_str)
                            geo = {
                                "latitude": details.latitude,
                                "longitude": details.longitude,
                                "country": details.country,
                            }
                            IP_GEO_CACHE[ip_str] = geo

                        latitude = geo["latitude"]
                        longitude = geo["longitude"]
                        country_val = geo["country"]
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

                    # try:
                    #     # fetch co2_aoer value if not already present
                    #     if aoer_val is None:
                    #         aoer_val = fetch_signal(latitude, longitude, EM_TOKEN, signal_type="co2_aoer")
                    #         measurement.co2_aoer = aoer_val

                    # except Exception as e:
                    #     measurement.co2_aoer = None
                    #     print(f"Error fetching aoer for IP {ip_str}: {e}")

                    carbon_cache[ip_str] = {
                        "country": country_val,
                        "co2_moer": moer_val,
                        "co2_aoer": aoer_val,
                    }

                carbon_value = _select_carbon_value(measurement, carbon_basis)
                _update_green_list(green_ip_list, ip_str, _vp_name, measurement.resolver or resolver or "local", carbon_value, green_list_size)
        
        print("Collecting traceroute results...")
        for o in ctrl.responses(timeout=timedelta(seconds=TRACEROUTE_TIMEOUT)):
            if not isinstance(o, ScamperTrace):
                continue  # skip non-traceroute responses
            vp_name = o.inst.name if hasattr(o.inst, 'name') else str(o.inst)
            measurement = _ensure_measurement(ip_results, vp_name, o.dst, resolver, cycle_start_iso)
            measurement.hop_count = (o.hop_count if o.hop_count else None)

        for e in ctrl.exceptions():
            print(f"Error during measurements: {e}")


    print("Scheduling pings to greenest IPs...")
    for i in ctrl.instances():
        for entry in green_ip_list:
            _, ip, vp_name, resolver = entry
            ctrl.do_ping(ip, inst=i)

    # Collect green ping results
    print("Collecting green ping results...")
    for o in ctrl.responses(timeout=timedelta(seconds=PING_TIMEOUT)):
        if not isinstance(o, ScamperPing):
            continue  # skip non-ping responses
        vp_name = o.inst.name if hasattr(o.inst, 'name') else str(o.inst)
        measurement = _ensure_measurement(ip_results, vp_name, o.dst, resolver, cycle_start_iso)
        measurement.avg_rtt_ms = (o.avg_rtt.total_seconds()*1000 if o.avg_rtt else None)
        measurement.min_rtt_ms = (o.min_rtt.total_seconds()*1000 if o.min_rtt else None)
        measurement.stddev_rtt_ms = (o.stddev_rtt.total_seconds()*1000 if o.stddev_rtt else None)
        measurement.gip = True  # mark as green IP

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
    # After each cycle, persist updated geolocation cache for next execution
    save_ip_geo_cache(IP_GEO_CACHE_PATH)

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
    # Load persistent IP geolocation cache once per execution
    load_ip_geo_cache(IP_GEO_CACHE_PATH)
    for i in range(cycles):
        cfg = load_config(CONFIG_PATH)
        apply_config(cfg)
        current_target = cfg.get("domain", target)
        current_resolvers = cfg.get("resolvers", resolvers)
        current_output = cfg.get("output_file", output_file)
        current_interval_minutes = cfg.get("interval_minutes", interval_minutes)
        current_cycles = cfg.get("cycles", cycles)

        # adjust planned start based on possibly updated interval
        cycle_start = first_start + timedelta(minutes=current_interval_minutes * i)
        now = datetime.now(timezone.utc)
        if now < cycle_start:
            sleep_seconds = (cycle_start - now).total_seconds()
            print(f"Waiting {sleep_seconds:.1f}s for next cycle start at {cycle_start.isoformat()}")
            time.sleep(sleep_seconds)
        planned_start_iso = cycle_start.isoformat()
        print(f"Starting cycle {i+1}/{current_cycles} at {planned_start_iso}")
        measure_vp(mux_path, current_target, output_file=current_output, resolvers=current_resolvers, cycle_start_iso=planned_start_iso, append_csv=True)

    


if __name__ == "__main__":
    # Example: run every 10 minutes for 3 cycles
    cfg = load_config(CONFIG_PATH)
    apply_config(cfg)
    run_cycles(
        "/run/ark/mux",
        target=cfg.get("domain", domain),
        output_file=cfg.get("output_file", default_output_file),
        resolvers=cfg.get("resolvers", resolvers),
        interval_minutes=cfg.get("interval_minutes", default_interval_minutes),
        cycles=cfg.get("cycles", default_cycles),
    )

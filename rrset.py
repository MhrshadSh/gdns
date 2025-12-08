#!/usr/bin/env python3
"""
Ark RRset latency + carbon-aware measurement runner.

Implements the 7-minute interval workflow described in the Ark proposed
measurement plan:
  1. DNS A queries from every DNS-capable VP (per resolver)
  2. Ping + traceroute each returned A-record IP from that VP
  3. Emit <dest_IP, Node, RTT, HC> tuples to the mux/output stream
  4. Lookup carbon intensity per tuple via IPinfo + WattTime
  5. Re-ping the "greenest" IP per VP
  6. Repeat for all configured resolvers
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from scamper import ScamperCtrl, ScamperFile  # type: ignore
except ImportError as exc:  # pragma: no cover - environment specific
    ScamperCtrl = None  # type: ignore
    ScamperFile = None  # type: ignore
    SCAMPER_IMPORT_ERROR = exc
else:
    SCAMPER_IMPORT_ERROR = None

try:
    import ipinfo  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    ipinfo = None

try:
    import requests
except ImportError:  # pragma: no cover - optional dependency
    requests = None

DEFAULT_INTERVAL_MINUTES = 7
PING_ATTEMPTS = 3
WATTTIME_TOKEN_TTL = 6 * 60  # seconds
RESPONSE_TIMEOUT_SECONDS = 45


@dataclass
class ResolverConfig:
    """Resolver description."""

    name: str
    address: Optional[str] = None


@dataclass
class MeasurementRecord:
    """Structured tuple emitted to the mux + downstream consumers."""

    dest_ip: str
    node: str
    domain: str
    resolver: str
    rtt_ms: Optional[float]
    hop_count: Optional[int]
    timestamp: str
    carbon_intensity: Optional[float] = None


class GeoCarbonClient:
    """Translates IPs to carbon intensity via IPinfo + WattTime."""

    def __init__(
        self,
        ipinfo_token: Optional[str],
        watttime_username: Optional[str],
        watttime_password: Optional[str],
    ) -> None:
        self._ipinfo_token = ipinfo_token
        self._watttime_username = watttime_username
        self._watttime_password = watttime_password
        self._wt_token: Optional[str] = None
        self._wt_token_ts: float = 0.0
        self._session = requests.Session() if requests else None
        self._ipinfo_handler = ipinfo.getHandler(ipinfo_token) if ipinfo and ipinfo_token else None

        self.enabled = bool(
            self._ipinfo_handler and self._session and watttime_username and watttime_password
        )
        if not self.enabled:
            logging.warning(
                "Geo-carbon lookup disabled (missing ipinfo token or WattTime credentials)."
            )

    def lookup(self, ip: str) -> Optional[float]:
        """Return estimated carbon intensity for the IP, or None."""
        if not self.enabled:
            return None

        try:
            details = self._ipinfo_handler.getDetails(ip)  # type: ignore[union-attr]
        except Exception as exc:  # pragma: no cover - network failures
            logging.warning("ipinfo lookup failed for %s: %s", ip, exc)
            return None

        lat = getattr(details, "latitude", None)
        lon = getattr(details, "longitude", None)
        if lat is None or lon is None:
            return None

        try:
            return self._fetch_carbon_float(float(lat), float(lon))
        except Exception as exc:  # pragma: no cover - network failures
            logging.warning("WattTime lookup failed for %s: %s", ip, exc)
            return None

    # --------------------------------------------------------------------- #
    # WattTime helpers
    def _fetch_carbon_float(self, lat: float, lon: float) -> Optional[float]:
        token = self._ensure_watttime_token()
        if not token or not self._session:
            return None

        headers = {"Authorization": f"Bearer {token}"}
        region_resp = self._session.get(
            "https://api2.watttime.org/v2/ba-from-loc",
            params={"latitude": lat, "longitude": lon},
            headers=headers,
            timeout=10,
        )
        region_resp.raise_for_status()
        region_data = region_resp.json()
        ba = region_data.get("abbrev")
        if not ba:
            return None

        carbon_resp = self._session.get(
            "https://api2.watttime.org/v2/index",
            params={"ba": ba},
            headers=headers,
            timeout=10,
        )
        carbon_resp.raise_for_status()
        carbon_data = carbon_resp.json()
        return carbon_data.get("percent") or carbon_data.get("value")

    def _ensure_watttime_token(self) -> Optional[str]:
        now = time.time()
        if self._wt_token and now - self._wt_token_ts < WATTTIME_TOKEN_TTL:
            return self._wt_token
        if not self._session or not (self._watttime_username and self._watttime_password):
            return None

        resp = self._session.get(
            "https://api2.watttime.org/v2/login",
            auth=(self._watttime_username, self._watttime_password),
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        token = data.get("token")
        if token:
            self._wt_token = token
            self._wt_token_ts = now
        return self._wt_token


class MeasurementRunner:
    """Coordinates Scamper measurements + enrichment pipeline."""

    def __init__(
        self,
        mux_path: str,
        domains: Sequence[str],
        resolvers: Sequence[ResolverConfig],
        interval_minutes: int,
        results_path: str,
        ipinfo_token: Optional[str],
        watttime_username: Optional[str],
        watttime_password: Optional[str],
        warts_output: str,
    ) -> None:
        if SCAMPER_IMPORT_ERROR:
            raise RuntimeError(
                "scamper python bindings are unavailable. "
                f"Import error: {SCAMPER_IMPORT_ERROR}"
            )

        self.domains = list(domains)
        self.resolvers = list(resolvers) or [ResolverConfig(name="system-default", address=None)]
        self.interval = timedelta(minutes=interval_minutes).total_seconds()
        self.results_path = results_path
        self.geo_client = GeoCarbonClient(ipinfo_token, watttime_username, watttime_password)

        self.outfile = ScamperFile(filename=warts_output, mode="w")  # type: ignore[call-arg]
        self.ctrl = ScamperCtrl(mux=mux_path, outfile=self.outfile)  # type: ignore[call-arg]
        self.vps = self._select_dns_capable_vps()
        self.instances = list(self.ctrl.instances())
        self.inst_lookup = {self._inst_name(inst): inst for inst in self.instances}
        self._results_fp = open(self.results_path, "a", encoding="utf-8")

    def close(self) -> None:
        """Release external resources."""
        try:
            self._results_fp.close()
        finally:
            self.outfile.close()
            self.ctrl.done()

    # ------------------------------------------------------------------ #
    def run(self, iterations: Optional[int] = None) -> None:
        """Run measurement cycles indefinitely (or for N iterations)."""
        iteration = 0
        try:
            while iterations is None or iteration < iterations:
                iteration += 1
                cycle_started = time.time()
                logging.info("Starting measurement cycle %s", iteration)
                cycle_records = self._run_cycle()
                self._emit_records(cycle_records)
                self._ping_greenest(cycle_records)

                elapsed = time.time() - cycle_started
                sleep_for = self.interval - elapsed
                if iterations is not None and iteration >= iterations:
                    break
                if sleep_for > 0:
                    logging.info("Sleeping %.1fs until next cycle", sleep_for)
                    time.sleep(sleep_for)
                else:
                    logging.info("Cycle exceeded interval by %.1fs; starting immediately", -sleep_for)
        finally:
            self.close()

    # ------------------------------------------------------------------ #
    def _run_cycle(self) -> List[Tuple[MeasurementRecord, object]]:
        records: List[Tuple[MeasurementRecord, object]] = []
        timestamp = datetime.now(timezone.utc).isoformat()
        for domain in self.domains:
            for resolver in self.resolvers:
                vp_ip_map = self._resolve_domain(domain, resolver)
                per_domain_records = self._measure_ips(domain, resolver, vp_ip_map, timestamp)
                records.extend(per_domain_records)
        return records

    def _select_dns_capable_vps(self) -> List[object]:
        vps = [vp for vp in self.ctrl.vps() if "primitive:dns" in getattr(vp, "tags", [])]
        if not vps:
            raise RuntimeError("No DNS-capable VPs available via mux.")
        self.ctrl.add_vps(vps)
        logging.info("Selected %d DNS-capable VPs.", len(vps))
        return vps

    def _resolve_domain(
        self, domain: str, resolver: ResolverConfig
    ) -> Dict[str, List[str]]:
        vp_ip_map: Dict[str, List[str]] = {}
        for vp in self.vps:
            vp_name = getattr(vp, "name", str(vp))
            dns_kwargs = {"qtype": "A", "sync": True}
            if resolver.address:
                dns_kwargs["server"] = resolver.address
            # Call ScamperCtrl.do_dns directly for this VP
            try:
                result = self.ctrl.do_dns(domain, vps=[vp], **dns_kwargs)
            except TypeError:
                # Fallback for environments where 'vps' is not supported
                result = self.ctrl.do_dns(domain, **dns_kwargs)
            if result is None:
                logging.warning("DNS lookup failed for %s via %s (%s)", domain, vp_name, resolver.name)
                continue
            ips = list(getattr(result, "ans_addrs", lambda: [])())
            vp_ip_map[vp_name] = ips
            logging.debug(
                "Resolved %s via %s/%s -> %s",
                domain,
                resolver.name,
                vp_name,
                ips,
            )
        return vp_ip_map

    def _measure_ips(
        self,
        domain: str,
        resolver: ResolverConfig,
        vp_ip_map: Dict[str, List[str]],
        timestamp: str,
    ) -> List[Tuple[MeasurementRecord, object]]:
        records: List[Tuple[MeasurementRecord, object]] = []
        measurement_meta: Dict[Tuple[str, str], Dict[str, str]] = {}

        # Schedule pings for all VPs/IPs concurrently.
        ping_tasks: Dict[str, Tuple[str, str]] = {}
        for vp_name, ips in vp_ip_map.items():
            inst = self.inst_lookup.get(vp_name)
            if not inst:
                logging.warning("Missing Scamper instance for VP %s; skipping.", vp_name)
                continue
            for ip in ips:
                key = (vp_name, ip)
                ping_id = self._task_id("ping", vp_name, resolver.name, domain, ip)
                measurement_meta[key] = {"ping_id": ping_id}
                ping_tasks[ping_id] = key
                self.ctrl.do_ping(ip, inst=inst, count=PING_ATTEMPTS, userid=ping_id)

        ping_results = self._collect_async_responses(ping_tasks, "ping")

        # Schedule traceroutes after pings complete to avoid mixing responses.
        trace_tasks: Dict[str, Tuple[str, str]] = {}
        for vp_name, ips in vp_ip_map.items():
            inst = self.inst_lookup.get(vp_name)
            if not inst:
                continue
            for ip in ips:
                key = (vp_name, ip)
                if key not in measurement_meta:
                    continue
                trace_id = self._task_id("trace", vp_name, resolver.name, domain, ip)
                measurement_meta[key]["trace_id"] = trace_id
                trace_tasks[trace_id] = key
                self.ctrl.do_trace(ip, inst=inst, protocol="udp", userid=trace_id)

        trace_results = self._collect_async_responses(trace_tasks, "traceroute")

        for (vp_name, ip), meta in measurement_meta.items():
            ping_obj = ping_results.get(meta["ping_id"])
            trace_obj = trace_results.get(meta.get("trace_id", ""))
            rtt_ms = self._extract_rtt_ms(ping_obj)
            hop_count = self._extract_hop_count(trace_obj)
            carbon = self.geo_client.lookup(ip)

            record = MeasurementRecord(
                dest_ip=ip,
                node=vp_name,
                domain=domain,
                resolver=resolver.name,
                rtt_ms=rtt_ms,
                hop_count=hop_count,
                timestamp=timestamp,
                carbon_intensity=carbon,
            )
            logging.info(
                "MUX tuple <%s, %s, %s ms, %s hops> (resolver=%s domain=%s)",
                record.dest_ip,
                record.node,
                f"{record.rtt_ms:.2f}" if record.rtt_ms is not None else "None",
                record.hop_count,
                record.resolver,
                record.domain,
            )
            records.append((record, self.inst_lookup.get(vp_name, vp_name)))
        return records

    def _ping_greenest(self, records: Sequence[Tuple[MeasurementRecord, object]]) -> None:
        best: Dict[Tuple[str, str, str], Tuple[MeasurementRecord, object]] = {}
        for record, vp in records:
            if record.carbon_intensity is None:
                continue
            key = (record.node, record.domain, record.resolver)
            current = best.get(key)
            if current is None or (record.carbon_intensity or 0) < (
                current[0].carbon_intensity or float("inf")
            ):
                best[key] = (record, vp)

        green_tasks: Dict[str, Tuple[str, MeasurementRecord]] = {}
        for (node, domain, resolver), (record, _vp) in best.items():
            inst = self.inst_lookup.get(node)
            if not inst:
                logging.warning("Missing instance for VP %s; skipping green ping.", node)
                continue
            task_id = self._task_id("green", node, resolver, domain, record.dest_ip)
            green_tasks[task_id] = (node, record)
            self.ctrl.do_ping(record.dest_ip, inst=inst, count=PING_ATTEMPTS, userid=task_id)

        responses = self._collect_async_responses(green_tasks, "green-ping")
        for task_id, (node, record) in green_tasks.items():
            rtt_ms = self._extract_rtt_ms(responses.get(task_id))
            logging.info(
                "Green ping %s/%s via %s -> %s ms",
                record.domain,
                record.resolver,
                node,
                f"{rtt_ms:.2f}" if rtt_ms is not None else "None",
            )
    def _collect_async_responses(
        self, tasks: Dict[str, object], label: str
    ) -> Dict[str, object]:
        """Wait for Scamper responses corresponding to the provided tasks."""
        if not tasks:
            return {}

        remaining = set(tasks.keys())
        collected: Dict[str, object] = {}
        timeout = timedelta(seconds=RESPONSE_TIMEOUT_SECONDS)
        for response in self.ctrl.responses(timeout=timeout):
            task_id = getattr(response, "userid", None)
            if task_id in remaining:
                collected[task_id] = response
                remaining.remove(task_id)
            if not remaining:
                break
        if remaining:
            logging.warning(
                "Timed out waiting for %d %s response(s); continuing.",
                len(remaining),
                label,
            )
        return collected

    @staticmethod
    def _inst_name(inst: object) -> str:
        vp = getattr(inst, "vp", None)
        if vp is not None and hasattr(vp, "name"):
            return getattr(vp, "name")
        return getattr(inst, "name", str(inst))

    @staticmethod
    def _task_id(kind: str, node: str, resolver: str, domain: str, ip: str) -> str:
        return f"{kind}|{node}|{resolver}|{domain}|{ip}"

    def _emit_records(self, records: Sequence[Tuple[MeasurementRecord, object]]) -> None:
        for record, _vp in records:
            self._results_fp.write(json.dumps(asdict(record)) + os.linesep)
        self._results_fp.flush()

    # ------------------------------------------------------------------ #
    # Helpers for interacting with Scamper
    def _invoke_ctrl(self, method: str, vp: object, *args, **kwargs):
        fn = getattr(self.ctrl, method)
        last_error: Optional[Exception] = None
        for param in ("vp", "vps"):
            call_kwargs = dict(kwargs)
            try:
                if param == "vp":
                    call_kwargs["vp"] = vp
                else:
                    call_kwargs["vps"] = [vp]
                return fn(*args, **call_kwargs)
            except TypeError as exc:
                last_error = exc
                continue
            except Exception as exc:
                logging.warning("%s failed: %s", method, exc)
                return None
        if last_error:
            logging.debug(
                "Falling back to ctrl.%s without vp specificity (reason: %s)", method, last_error
            )
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            logging.warning("%s failed without vp: %s", method, exc)
            return None

    @staticmethod
    def _extract_rtt_ms(ping_obj) -> Optional[float]:
        avg_rtt = getattr(ping_obj, "avg_rtt", None)
        if avg_rtt is None:
            return None
        if hasattr(avg_rtt, "total_seconds"):
            return avg_rtt.total_seconds() * 1000
        try:
            return float(avg_rtt) * 1000
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_hop_count(trace_obj) -> Optional[int]:
        if trace_obj is None:
            return None
        if hasattr(trace_obj, "hop_count"):
            hop_count = trace_obj.hop_count  # attr or method?
            if callable(hop_count):
                try:
                    return int(hop_count())
                except Exception:
                    pass
            else:
                try:
                    return int(hop_count)
                except (TypeError, ValueError):
                    pass
        hops = getattr(trace_obj, "hops", None)
        if hops and hasattr(hops, "__len__"):
            return len(hops)
        return None


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ark RRset latency + carbon aware measurement runner"
    )
    parser.add_argument("--mux", dest="mux_path", required=True, help="Path to Scamper mux socket")
    parser.add_argument(
        "--domains",
        nargs="+",
        required=True,
        help="List of domains to monitor",
    )
    parser.add_argument(
        "--resolvers",
        nargs="+",
        default=[],
        help="Resolvers to test (format name=address, address defaults to system)",
    )
    parser.add_argument(
        "--interval-minutes",
        type=int,
        default=DEFAULT_INTERVAL_MINUTES,
        help="Measurement cadence (default: 7 minutes)",
    )
    parser.add_argument(
        "--results-jsonl",
        default="measurements.jsonl",
        help="Where to append structured tuples",
    )
    parser.add_argument(
        "--warts-output",
        default="measurements.warts",
        help="Where to store native Scamper outputs",
    )
    parser.add_argument("--iterations", type=int, help="Stop after N cycles (omit to run forever)")
    parser.add_argument("--ipinfo-token", help="API token for ipinfo lookups")
    parser.add_argument("--watttime-username", help="WattTime username")
    parser.add_argument("--watttime-password", help="WattTime password")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity",
    )
    return parser.parse_args(argv)


def parse_resolvers(raw_resolvers: Sequence[str]) -> List[ResolverConfig]:
    if not raw_resolvers:
        return [ResolverConfig(name="system-default", address=None)]
    resolvers: List[ResolverConfig] = []
    for raw in raw_resolvers:
        if "=" in raw:
            name, address = raw.split("=", 1)
        else:
            name, address = raw, raw
        resolvers.append(ResolverConfig(name=name.strip(), address=address.strip() or None))
    return resolvers


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    resolvers = parse_resolvers(args.resolvers)

    runner = MeasurementRunner(
        mux_path=args.mux_path,
        domains=args.domains,
        resolvers=resolvers,
        interval_minutes=args.interval_minutes,
        results_path=args.results_jsonl,
        ipinfo_token=args.ipinfo_token or os.getenv("IPINFO_TOKEN"),
        watttime_username=args.watttime_username or os.getenv("WATTTIME_USERNAME"),
        watttime_password=args.watttime_password or os.getenv("WATTTIME_PASSWORD"),
        warts_output=args.warts_output,
    )
    try:
        runner.run(iterations=args.iterations)
    except KeyboardInterrupt:
        logging.info("Interrupted; shutting down.")
    finally:
        runner.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())


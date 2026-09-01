from __future__ import annotations

import ipaddress
import os
import random
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanDevice:
    ip: str
    mac: str

    def as_dict(self) -> dict:
        return {"ip": self.ip, "mac": self.mac.upper()}


def validate_cidr(cidr: str) -> str:
    """Validate an IPv4 CIDR and keep classroom scans to a sensible size."""
    network = ipaddress.ip_network(cidr, strict=False)
    if network.version != 4:
        raise ValueError("Kun IPv4-netværk understøttes.")
    if network.prefixlen < 16:
        raise ValueError("Netværket er for stort. Brug /16 eller et mindre subnet, fx /24.")
    return str(network)


def _demo_scan(cidr: str, known: list[dict] | None = None) -> list[dict]:
    """Development fallback. Enable with IP_SENTINEL_SCAN_MODE=demo."""
    network = ipaddress.ip_network(validate_cidr(cidr), strict=False)
    devices: list[dict] = []
    for item in known or []:
        try:
            if ipaddress.ip_address(item["ip"]) in network and random.random() > 0.15:
                devices.append(
                    {
                        "ip": item["ip"],
                        "mac": (item.get("mac") or _random_mac()).upper(),
                    }
                )
        except (ValueError, KeyError):
            continue

    hosts = list(network.hosts())
    if hosts:
        for candidate in hosts[-min(30, len(hosts)):]:
            ip = str(candidate)
            if not any(x["ip"] == ip for x in devices) and not any(
                x.get("ip") == ip for x in (known or [])
            ):
                devices.append({"ip": ip, "mac": _random_mac()})
                break
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def _random_mac() -> str:
    values = [0x02, random.randrange(256), random.randrange(256), random.randrange(256), random.randrange(256), random.randrange(256)]
    return ":".join(f"{v:02X}" for v in values)


def scan_network(
    cidr: str,
    *,
    timeout: float = 2.0,
    interface: str | None = None,
    known: list[dict] | None = None,
) -> list[dict]:
    """
    Discover active IPv4 hosts on the local broadcast domain using ARP.

    This is the same Layer-2 principle as Ether(dst=ff:ff:ff:ff:ff:ff)/ARP(...),
    but pdst is a CIDR instead of one host, and srp() collects the replies.
    """
    cidr = validate_cidr(cidr)
    timeout = max(0.25, min(float(timeout), 10.0))

    if os.getenv("IP_SENTINEL_SCAN_MODE", "real").lower() == "demo":
        return _demo_scan(cidr, known)

    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as exc:
        raise RuntimeError(
            "Scapy er ikke installeret. Kør: pip install -r requirements.txt"
        ) from exc

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    kwargs = {"timeout": timeout, "verbose": False}
    if interface:
        kwargs["iface"] = interface

    try:
        answered, _ = srp(packet, **kwargs)
    except PermissionError as exc:
        raise RuntimeError(
            "Scapy mangler rettigheder til raw sockets. Kør programmet med de nødvendige netværksrettigheder."
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"Netværksscanning fejlede: {exc}") from exc

    found: dict[str, ScanDevice] = {}
    for _sent, received in answered:
        ip = str(received.psrc)
        mac = str(received.hwsrc).upper()
        found[ip] = ScanDevice(ip=ip, mac=mac)

    return [
        device.as_dict()
        for device in sorted(found.values(), key=lambda d: ipaddress.ip_address(d.ip))
    ]

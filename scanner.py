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

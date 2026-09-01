from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import threading
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from database import Database
from notifier import send_email_alert
from scanner import scan_network, validate_cidr


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("IP_SENTINEL_DB", BASE_DIR / "data" / "ip_sentinel.db"))
DEFAULT_CIDR = os.getenv("IP_SENTINEL_CIDR", "192.168.2.0/24")
DEFAULT_INTERFACE = os.getenv("IP_SENTINEL_INTERFACE") or None

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
app.config["JSON_SORT_KEYS"] = False

db = Database(DB_PATH)
scan_lock = threading.Lock()
scheduler = {"thread": None, "stop": None, "interval": None, "cidr": None, "timeout": None}

MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def normalize_mac(value: str | None) -> str:
    return (value or "").strip().replace("-", ":").upper()


def validate_reservation(data: dict) -> dict:
    try:
        ip = str(ipaddress.ip_address(str(data.get("ip", "")).strip()))
    except ValueError as exc:
        raise ValueError("Ugyldig IPv4-adresse.") from exc
    if ":" in ip:
        raise ValueError("Kun IPv4-adresser understøttes.")

    name = str(data.get("name", "")).strip()
    mac = normalize_mac(data.get("mac"))
    owner = str(data.get("owner", "")).strip()
    note = str(data.get("note", "")).strip()

    if not name:
        raise ValueError("Enhedsnavn skal udfyldes.")
    if len(name) > 60 or len(owner) > 60 or len(note) > 200:
        raise ValueError("Et eller flere tekstfelter er for lange.")
    if mac and not MAC_RE.fullmatch(mac):
        raise ValueError("Ugyldig MAC-adresse. Brug fx AA:BB:CC:DD:EE:FF.")

    return {"ip": ip, "name": name, "mac": mac, "owner": owner, "note": note}


def require_auth(fn):
    """Optional Basic Auth. Enable by setting both user and password env vars."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username = os.getenv("IP_SENTINEL_USER")
        password = os.getenv("IP_SENTINEL_PASSWORD")
        if not username or not password:
            return fn(*args, **kwargs)
        auth = request.authorization
        if not auth or not (
            hmac.compare_digest(auth.username or "", username)
            and hmac.compare_digest(auth.password or "", password)
        ):
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="IP Sentinel"'},
            )
        return fn(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    # This project intentionally uses one inline script/style block in the supplied HTML.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    )
    return response


@app.route("/")
@require_auth
def index():
    return render_template("index.html")


@app.get("/api/health")
@require_auth
def health():
    return jsonify(
        {
            "ok": True,
            "scan_mode": os.getenv("IP_SENTINEL_SCAN_MODE", "real"),
            "database": str(DB_PATH),
            "default_cidr": DEFAULT_CIDR,
        }
    )


@app.get("/api/reservations")
@require_auth
def list_reservations():
    return jsonify(db.list_reservations())


@app.post("/api/reservations")
@require_auth
def save_reservation():
    try:
        payload = request.get_json(force=True)
        reservation = validate_reservation(payload)
        original_ip = payload.get("original_ip") or None
        if original_ip:
            original_ip = str(ipaddress.ip_address(original_ip))
        db.upsert_reservation(reservation, original_ip)
        db.add_log("INFO", f"Reservation gemt: {reservation['ip']}")
        return jsonify(reservation), 201
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.delete("/api/reservations/<path:ip>")
@require_auth
def delete_reservation(ip: str):
    try:
        normalized = str(ipaddress.ip_address(ip))
    except ValueError:
        return jsonify({"error": "Ugyldig IP-adresse."}), 400
    if db.delete_reservation(normalized):
        db.add_log("INFO", f"Reservation slettet: {normalized}")
        return jsonify({"ok": True})
    return jsonify({"error": "Reservation ikke fundet."}), 404


@app.post("/api/reservations/import")
@require_auth
def import_reservations():
    try:
        payload = request.get_json(force=True)
        raw = payload if isinstance(payload, list) else payload.get("reservations")
        if not isinstance(raw, list):
            raise ValueError("JSON skal indeholde en liste af reservationer.")
        if len(raw) > 4096:
            raise ValueError("For mange reservationer i importfilen.")
        clean = [validate_reservation(item) for item in raw]
        if len({item["ip"] for item in clean}) != len(clean):
            raise ValueError("Importen indeholder dublerede IP-adresser.")
        db.replace_reservations(clean)
        db.add_log("INFO", f"Importerede {len(clean)} reservationer.")
        return jsonify({"ok": True, "count": len(clean)})
    except (ValueError, TypeError, AttributeError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/demo-data")
@require_auth
def demo_data():
    data = [
        {"ip": "192.168.2.10", "name": "Gateway", "mac": "02:42:AC:11:00:01", "owner": "Netværk", "note": "Router / gateway"},
        {"ip": "192.168.2.20", "name": "Kontor-PC", "mac": "A4:5E:60:8B:11:20", "owner": "Administration", "note": "Fast arbejdsstation"},
        {"ip": "192.168.2.30", "name": "Printer-01", "mac": "70:85:C2:19:6F:30", "owner": "Kontor", "note": "Netværksprinter"},
        {"ip": "192.168.2.40", "name": "Raspberry-Pi", "mac": "B8:27:EB:7A:14:40", "owner": "IP Sentinel", "note": "Scanner og webserver"},
    ]
    db.replace_reservations(data)
    db.add_log("INFO", "Demo-database indlæst.")
    return jsonify(data)


def classify_devices(found: list[dict], reservations: list[dict]) -> list[dict]:
    known = {item["ip"]: item for item in reservations}
    result = []
    for device in found:
        ip = device["ip"]
        mac = normalize_mac(device.get("mac"))
        reservation = known.get(ip)
        if not reservation:
            result.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "name": "Ukendt enhed",
                    "status": "bad",
                    "label": "UKENDT IP",
                    "reason": f"Ukendt aktiv IP: {ip} ({mac})",
                }
            )
            continue

        expected_mac = normalize_mac(reservation.get("mac"))
        if expected_mac and expected_mac != mac:
            result.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "name": reservation["name"],
                    "status": "warn",
                    "label": "MAC-MISMATCH",
                    "reason": f"MAC-uoverensstemmelse på {ip}: forventet {expected_mac}, fundet {mac}",
                }
            )
            continue

        result.append(
            {
                "ip": ip,
                "mac": mac,
                "name": reservation["name"],
                "status": "good",
                "label": "GODKENDT",
                "reason": "",
            }
        )
    return result


def perform_scan(cidr: str, timeout: float, *, source: str = "manuel") -> dict:
    cidr = validate_cidr(cidr)
    reservations = db.list_reservations()

    if not scan_lock.acquire(blocking=False):
        raise RuntimeError("En scanning kører allerede.")
    try:
        started = utc_now()
        db.add_log("INFO", f"Scanning startet ({source}): {cidr}")
        found = scan_network(
            cidr,
            timeout=timeout,
            interface=DEFAULT_INTERFACE,
            known=reservations,
        )
        devices = classify_devices(found, reservations)
        finished = utc_now()

        scan_id = db.save_scan(
            cidr=cidr,
            started_at=started,
            finished_at=finished,
            devices=devices,
        )
        issue_count = sum(1 for d in devices if d["status"] != "good")
        db.add_log("OK", f"Scanning færdig: {len(devices)} aktive enheder, {issue_count} uoverensstemmelser.")

        issues = [d for d in devices if d["status"] != "good"]
        for issue in issues:
            db.add_log("ALARM", issue["reason"])

        if issues:
            body = "IP Sentinel fandt følgende uoverensstemmelser:\n\n" + "\n".join(
                f"- {item['reason']}" for item in issues
            )
            try:
                if send_email_alert("IP Sentinel alarm", body):
                    db.add_log("INFO", "Alarm sendt via e-mail.")
            except Exception as exc:  # Alarm transport must not break the scan result.
                db.add_log("WARNING", f"E-mailalarm fejlede: {exc}")

        return {
            "id": scan_id,
            "cidr": cidr,
            "started_at": started,
            "finished_at": finished,
            "active_count": len(devices),
            "issue_count": issue_count,
            "devices": devices,
        }
    finally:
        scan_lock.release()


@app.post("/api/scan")
@require_auth
def scan():
    try:
        data = request.get_json(silent=True) or {}
        cidr = str(data.get("cidr") or DEFAULT_CIDR)
        timeout = float(data.get("timeout", 2))
        if not 0.25 <= timeout <= 10:
            raise ValueError("Timeout skal være mellem 0,25 og 10 sekunder.")
        return jsonify(perform_scan(cidr, timeout))
    except (ValueError, RuntimeError) as exc:
        db.add_log("WARNING", f"Scanning fejlede: {exc}")
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        db.add_log("WARNING", f"Uventet scanningsfejl: {exc}")
        return jsonify({"error": "Scanning kunne ikke gennemføres.", "detail": str(exc)}), 500


@app.get("/api/scans")
@require_auth
def scans():
    return jsonify(db.list_scans(request.args.get("limit", 25)))


@app.get("/api/scans/latest")
@require_auth
def latest_scan():
    return jsonify(db.latest_scan())


@app.get("/api/logs")
@require_auth
def logs():
    return jsonify(db.list_logs(request.args.get("limit", 250)))


@app.delete("/api/logs")
@require_auth
def clear_logs():
    db.clear_logs()
    return jsonify({"ok": True})


@app.get("/api/alerts")
@require_auth
def alerts():
    return jsonify(db.list_logs(request.args.get("limit", 50), level="ALARM"))


def _scheduler_loop(interval: float, cidr: str, timeout: float, stop_event: threading.Event):
    while not stop_event.wait(interval):
        try:
            perform_scan(cidr, timeout, source="planlagt")
        except Exception as exc:
            db.add_log("WARNING", f"Planlagt scanning fejlede: {exc}")


@app.post("/api/schedule")
@require_auth
def start_schedule():
    try:
        data = request.get_json(force=True)
        amount = float(data.get("amount", 30))
        unit = str(data.get("unit", "seconds"))
        cidr = validate_cidr(str(data.get("cidr") or DEFAULT_CIDR))
        timeout = float(data.get("timeout", 2))
        interval = amount * (60 if unit == "minutes" else 1)
        if interval < 5 or interval > 86400:
            raise ValueError("Interval skal være mellem 5 sekunder og 24 timer.")
        if not 0.25 <= timeout <= 10:
            raise ValueError("Timeout skal være mellem 0,25 og 10 sekunder.")

        stop_schedule_internal()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=_scheduler_loop,
            args=(interval, cidr, timeout, stop_event),
            daemon=True,
            name="ip-sentinel-scheduler",
        )
        scheduler.update(
            {"thread": thread, "stop": stop_event, "interval": interval, "cidr": cidr, "timeout": timeout}
        )
        thread.start()
        db.add_log("INFO", f"Planlagt scanning startet: hvert {interval:g} sekund på {cidr}.")
        return jsonify(schedule_status())
    except (ValueError, TypeError) as exc:
        return jsonify({"error": str(exc)}), 400


def stop_schedule_internal() -> None:
    stop_event = scheduler.get("stop")
    if stop_event:
        stop_event.set()
    scheduler.update({"thread": None, "stop": None, "interval": None, "cidr": None, "timeout": None})


def schedule_status() -> dict:
    thread = scheduler.get("thread")
    active = bool(thread and thread.is_alive())
    return {
        "active": active,
        "interval_seconds": scheduler.get("interval") if active else None,
        "cidr": scheduler.get("cidr") if active else None,
    }


@app.delete("/api/schedule")
@require_auth
def stop_schedule():
    stop_schedule_internal()
    db.add_log("INFO", "Planlagt scanning stoppet.")
    return jsonify({"active": False})


@app.get("/api/schedule")
@require_auth
def get_schedule():
    return jsonify(schedule_status())


@app.errorhandler(413)
def too_large(_exc):
    return jsonify({"error": "Request er for stor."}), 413


if __name__ == "__main__":
    # use_reloader=False prevents Flask's development reloader from creating
    # a second scheduler process/thread during classroom demonstrations.
    db.add_log("INFO", "IP Sentinel backend startet.")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False, use_reloader=False)

from __future__ import annotations

import pytest

import app as app_module


GOOD_MAC = "AA:BB:CC:DD:EE:01"
MISMATCH_MAC = "AA:BB:CC:DD:EE:99"
UNKNOWN_MAC = "AA:BB:CC:DD:EE:02"


def reservation(ip: str = "192.168.2.10") -> dict:
    return {
        "ip": ip,
        "name": "Printer",
        "mac": GOOD_MAC,
        "owner": "Operations",
        "note": "Front office",
    }


def test_health_and_index_are_available(client):
    page = client.get("/")
    health = client.get("/api/health")

    assert page.status_code == 200
    assert health.status_code == 200
    assert health.get_json()["ok"] is True
    assert health.get_json()["default_cidr"] == "192.168.2.0/24"
    assert health.headers["X-Content-Type-Options"] == "nosniff"
    assert health.headers["X-Frame-Options"] == "DENY"


def test_reservation_lifecycle_and_validation(client):
    created = client.post("/api/reservations", json=reservation())
    assert created.status_code == 201
    assert created.get_json()["ip"] == "192.168.2.10"

    edited = reservation("192.168.2.11")
    edited["name"] = "Updated printer"
    edited["original_ip"] = "192.168.2.10"
    response = client.post("/api/reservations", json=edited)
    assert response.status_code == 201

    listed = client.get("/api/reservations")
    assert listed.get_json() == [
        {
            "ip": "192.168.2.11",
            "name": "Updated printer",
            "mac": GOOD_MAC,
            "owner": "Operations",
            "note": "Front office",
        }
    ]

    invalid = client.post(
        "/api/reservations",
        json={"ip": "192.168.2.11", "name": "", "mac": "bad"},
    )
    assert invalid.status_code == 400
    assert "error" in invalid.get_json()

    deleted = client.delete("/api/reservations/192.168.2.11")
    assert deleted.status_code == 200
    assert client.delete("/api/reservations/192.168.2.11").status_code == 404


def test_reservation_import_rejects_duplicates_and_accepts_clean_data(client):
    imported = client.post(
        "/api/reservations/import",
        json={"reservations": [reservation(), reservation("192.168.2.12")]},
    )
    assert imported.status_code == 200
    assert imported.get_json() == {"ok": True, "count": 2}

    duplicate = client.post(
        "/api/reservations/import",
        json=[reservation(), reservation()],
    )
    assert duplicate.status_code == 400
    assert "dublerede" in duplicate.get_json()["error"]


def test_scan_persists_classified_devices_logs_and_alert(client, monkeypatch):
    client.post("/api/reservations", json=reservation())
    client.post("/api/reservations", json=reservation("192.168.2.11"))
    sent_alerts = []

    def fake_scan_network(cidr, *, timeout, interface, known):
        assert cidr == "192.168.2.0/24"
        assert timeout == 1.5
        assert known[0]["ip"] == "192.168.2.10"
        return [
            {"ip": "192.168.2.10", "mac": GOOD_MAC.lower()},
            {"ip": "192.168.2.11", "mac": MISMATCH_MAC},
            {"ip": "192.168.2.12", "mac": UNKNOWN_MAC},
        ]

    def fake_send_email(subject, body):
        sent_alerts.append((subject, body))
        return True

    monkeypatch.setattr(app_module, "scan_network", fake_scan_network)
    monkeypatch.setattr(app_module, "send_email_alert", fake_send_email)

    response = client.post(
        "/api/scan",
        json={"cidr": "192.168.2.0/24", "timeout": 1.5},
    )

    assert response.status_code == 200
    result = response.get_json()
    assert result["active_count"] == 3
    assert result["issue_count"] == 2
    assert [device["status"] for device in result["devices"]] == ["good", "warn", "bad"]
    assert result["devices"][0]["name"] == "Printer"
    assert result["devices"][2]["name"] == "Unknown Device"
    assert len(sent_alerts) == 1

    latest = client.get("/api/scans/latest").get_json()
    assert latest["id"] == result["id"]
    assert len(latest["devices"]) == 3
    assert client.get("/api/scans").get_json()[0]["issue_count"] == 2
    assert len(client.get("/api/alerts").get_json()) == 1

    logs = client.get("/api/logs").get_json()
    assert any("Discovery finished" in log["message"] for log in logs)
    assert any(log["level"] == "TRUSTED" for log in logs)


def test_basic_auth_can_protect_api(client, monkeypatch):
    monkeypatch.setenv("IP_SENTINEL_USER", "admin")
    monkeypatch.setenv("IP_SENTINEL_PASSWORD", "secret")

    unauthorized = client.get("/api/health")
    authorized = client.get("/api/health", auth=("admin", "secret"))

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200

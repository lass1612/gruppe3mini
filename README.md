# IP Sentinel – Python + Scapy

Komplet backend til IP Sentinel-opgaven. Flask serverer webinterfacet, SQLite gemmer reservationer/logs/scanninger, og Scapy laver en rigtig ARP-scan af det lokale subnet.

## Filer

- `app.py` – Flask API, sammenligning, alarmflow og scheduler
- `scanner.py` – Layer-2 ARP-scanning med Scapy
- `database.py` – SQLite og parameteriserede SQL-queries
- `notifier.py` – valgfri e-mailalarm via SMTP
- `templates/index.html` – frontend koblet til Python API
- `data/ip_sentinel.db` – oprettes automatisk første gang
- `requirements.txt` – Python dependencies

## Installation på Raspberry Pi / Linux

```bash
cd ip_sentinel_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Start i demo-mode først

```bash
export IP_SENTINEL_SCAN_MODE=demo
python3 app.py
```

Åbn derefter:

`http://<raspberry-pi-ip>:5000`

### Rigtig ARP-scan

Scapy bruger raw sockets. Til en hurtig undervisningsdemo kan programmet startes med de nødvendige rettigheder:

```bash
sudo .venv/bin/python app.py
```

I en produktionsløsning bør webserveren ikke køre som root; scanner-delen bør isoleres og få kun den nødvendige netværkskapabilitet.

Sæt evt. interface før start:

```bash
export IP_SENTINEL_INTERFACE=eth0
export IP_SENTINEL_CIDR=192.168.2.0/24
sudo -E .venv/bin/python app.py
```

## Windows

Installer Python, Npcap og dependencies. Start terminal/PowerShell som administrator. Hvis Scapy vælger forkert interface, sæt `IP_SENTINEL_INTERFACE` til det interface Scapy/Npcap bruger.

## Hvad sker der ved Scan netværk?

1. HTML sender `POST /api/scan` med CIDR og timeout.
2. `scanner.py` bygger `Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)`.
3. `srp()` sender ARP-broadcast og samler svar med IP + MAC.
4. Python henter reservationerne fra SQLite.
5. Fundne enheder klassificeres som `GODKENDT`, `UKENDT IP` eller `MAC-MISMATCH`.
6. Scanresultat, logs og alarmer gemmes i SQLite.
7. Frontend viser resultatet.
8. Hvis SMTP er konfigureret, sendes uoverensstemmelser også som e-mail.

## Sikkerhed i løsningen

- SQL Injection: alle SQL-værdier bruger `?`-parametre i `database.py`.
- XSS: frontend bygger tabeller med `textContent`, ikke rå bruger-HTML.
- Inputvalidering: Python validerer IPv4, CIDR, MAC og tekstlængder server-side.
- Begrænset scanning: backend afviser netværk større end `/16`.
- CSP, `X-Frame-Options`, `nosniff` og øvrige HTTP security headers.
- Valgfri HTTP Basic Auth via miljøvariabler.
- Audit log i SQLite.

## Valgfri login

```bash
export IP_SENTINEL_USER=admin
export IP_SENTINEL_PASSWORD='et-langt-password'
python3 app.py
```

Browseren viser derefter sin standard login-dialog.

## Valgfri e-mailalarm

Eksempel:

```bash
export IP_SENTINEL_SMTP_HOST=smtp.example.com
export IP_SENTINEL_SMTP_PORT=587
export IP_SENTINEL_SMTP_USER=brugernavn
export IP_SENTINEL_SMTP_PASSWORD=password
export IP_SENTINEL_ALERT_TO=modtager@example.com
python3 app.py
```

## API

- `GET /api/health`
- `GET /api/reservations`
- `POST /api/reservations`
- `DELETE /api/reservations/<ip>`
- `POST /api/reservations/import`
- `POST /api/demo-data`
- `POST /api/scan`
- `GET /api/scans`
- `GET /api/scans/latest`
- `GET /api/logs`
- `DELETE /api/logs`
- `GET /api/alerts`
- `GET /api/schedule`
- `POST /api/schedule`
- `DELETE /api/schedule`

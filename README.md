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

## Opsætning og Eksekvering

Scapy bruger raw sockets til at udføre ARP-scanning. Dette kræver særlige rettigheder på både Windows og Linux.
Vi har delt opsætningen op i to klare stier afhængig af dit operativsystem. Det anbefales at bruge et virtuelt Python-miljø.

---

### Vejledning: Windows

1. **Opret og aktiver et virtuelt miljø:**
   Start din terminal (PowerShell) som **Administrator**, gå til projektmappen, og kør:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\activate
   ```

2. **Installer dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Kør serveren:**
   Husk, at terminalen *skal* køre som **Administrator** for at Scapy kan få adgang til raw sockets.
   ```powershell
   .\.venv\Scripts\python.exe app.py
   ```
   *Bemærk: Hvis Scapy vælger det forkerte interface, kan du angive det manuelt:*
   ```powershell
   $env:IP_SENTINEL_INTERFACE="Navn-paa-interface"
   .\.venv\Scripts\python.exe app.py
   ```

4. **Åbn webinterfacet:**
   Gå til `http://localhost:5000` i din browser.

---

### Vejledning: Raspberry Pi / Linux

1. **Opret og aktiver et virtuelt miljø:**
   Gå til projektmappen, og kør:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Installer dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Kør serveren med administratorrettigheder:**
   Brug `sudo` til at køre Python-fortolkeren fra dit virtuelle miljø, da raw sockets kræver root.
   ```bash
   sudo .venv/bin/python app.py
   ```
   *Bemærk: Hvis Scapy vælger det forkerte interface, eller du vil sætte et standard CIDR:*
   ```bash
   export IP_SENTINEL_INTERFACE=eth0
   export IP_SENTINEL_CIDR=192.168.2.0/24
   sudo -E .venv/bin/python app.py
   ```
   For nem opstart kan du også bruge hjælpe-scriptet `start_real_pi.sh`.

4. **Åbn webinterfacet:**
   Gå til `http://localhost:5000` i din browser.

---

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
.venv/bin/python app.py
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
.venv/bin/python app.py
```

## API

- `GET /api/health`
- `GET /api/reservations`
- `POST /api/reservations`
- `DELETE /api/reservations/<ip>`
- `POST /api/reservations/import`
- `POST /api/scan`
- `GET /api/scans`
- `GET /api/scans/latest`
- `GET /api/logs`
- `DELETE /api/logs`
- `GET /api/alerts`
- `GET /api/schedule`
- `POST /api/schedule`
- `DELETE /api/schedule`

# Traceframe

Traceframe is a local Flask workspace for exploring packet metadata from captures you are authorized to inspect. It does not capture live traffic, scan networks, analyze payloads, or contact external services at runtime.

## Setup and run (Windows PowerShell)

From the `homeworks/Homework6` folder:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000. The development server binds only to localhost; it is intended for a single local user, not internet deployment. Press Ctrl+C to stop it.

Run the synthetic tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

## Supported input and limits

- Binary `.pcap` and `.pcapng` files with Ethernet or raw IPv4/IPv6 link types. The extension must match the file contents. Text logs are not supported.
- PCAPNG must have one section and one interface, with enhanced or obsolete packet blocks. Simple packet blocks and multiple interfaces or sections are rejected.
- The upload request is limited to 64 MiB including form overhead, and a capture to 100,000 packets. At most 10 analyses can be retained in the process.
- The table shows captured byte lengths, which can be less than the original on-wire lengths for truncated packets. It does not infer direction; IP addresses and ports may be unavailable for non-IP or truncated frames. IPv6 extension headers and fragmented packets may prevent protocol or port identification. Captured timestamps and filter inputs are UTC.
- Summaries and charts reflect the current filters. IP filters match address text; port and protocol filters match exactly. The table shows 50 packets per page.

## Data handling

Uploads are untrusted and are never executed. Flask/Werkzeug may temporarily spool larger multipart uploads to the operating system's temporary directory while handling the request; these temporary files are closed and removed when the request ends. The application does not intentionally save capture files. Packet bytes are discarded after parsing; only packet metadata, including IP addresses, remains in server memory. IP addresses can themselves be sensitive. Clear the analysis to remove its retained metadata; idle analyses expire after 30 minutes and are removed by a background cleanup task (within about one minute), or when the process exits. Session data is process-local and does not survive a restart. Avoid exposing this development server to other users or networks.

## Project structure

```text
app.py                    Flask routes, session lifecycle, summaries, and charts
capture_analysis.py       Capture validation, metadata parsing, and filtering
requirements.txt          Python dependencies
templates/dashboard.html  Jinja dashboard
static/style.css          Responsive styling
static/dashboard.js       File selection feedback
tests/test_capture_analysis.py  Synthetic parser and workflow tests
```
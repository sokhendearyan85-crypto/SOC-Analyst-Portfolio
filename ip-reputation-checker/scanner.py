import csv
import html
import ipaddress
import json
import os
import smtplib
import ssl
import time
import urllib.error
import urllib.request

from io import StringIO
from pathlib import Path
from datetime import datetime
from email.message import EmailMessage



BASE_DIR = Path(__file__).resolve().parent
CSV_FILE = BASE_DIR / "scan_results.csv"

TIMEOUT = 20

FEEDS = {
    "IPsum Level 3":
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/ipsum_3.ipset",

    "DShield":
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield.netset",

    "Abuse.ch Feodo Tracker":
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",

     "AbuseIPDB 30 Days":
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/abuseipdb_30d.ipset",

    "Threat Intel IPv4":
        "https://raw.githubusercontent.com/ziyadnz/threat-intel-ip-feeds/main/output/hourlyIPv4.txt",
}

VT_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

COLUMNS = [
    "timestamp",
    "ip",
    "status",
    "feed_matches",
    "feed_score",
    "vt_status",
    "vt_malicious",
    "vt_suspicious",
    "vt_total",
    "details",
]


# =====================================================
# HELPER FUNCTIONS
# =====================================================

def get_time():
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def download_text(url, headers=None):
    request = urllib.request.Request(
        url,
        headers=headers or {
            "User-Agent": "Cybersecurity-IP-Scanner/1.0"
        }
    )

    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", errors="replace")


# =====================================================
# THREAT FEEDS
# =====================================================

def load_feed(name, url):
    networks = set()

    try:
        content = download_text(url)

        for line in content.splitlines():
            line = line.strip()

            if not line or line.startswith(("#", ";", "//")):
                continue

            # Ignore CSV headers and non-IP lines.
            token = line.split()[0].strip(",")

            try:
                network = ipaddress.ip_network(token, strict=False)

                if network.version == 4:
                    networks.add(network)

            except ValueError:
                continue

        print(f"[+] {name}: {len(networks)} entries loaded")
        return networks

    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        print(f"[!] {name} download failed: {error}")
        return None


def load_all_feeds():
    loaded_feeds = {}

    print("\nDownloading threat intelligence feeds...\n")

    for name, url in FEEDS.items():
        result = load_feed(name, url)

        if result is not None:
            loaded_feeds[name] = result

    print(f"\nAvailable feeds: {len(loaded_feeds)}/{len(FEEDS)}")
    return loaded_feeds


def match_feeds(ip_obj, loaded_feeds):
    matches = []

    for name, networks in loaded_feeds.items():
        if any(ip_obj in network for network in networks):
            matches.append(name)

    return matches


# =====================================================
# VIRUSTOTAL API
# =====================================================

def check_virustotal(ip_text):
    api_key = os.environ.get("VT_API_KEY", "").strip()

    if not api_key:
        return {
            "status": "NOT CONFIGURED",
            "malicious": "",
            "suspicious": "",
            "total": "",
            "details": "VirusTotal API key is not configured."
        }

    ip_obj = ipaddress.ip_address(ip_text)

    # Only query globally routable IP addresses.
    if not ip_obj.is_global:
        return {
            "status": "SKIPPED",
            "malicious": "",
            "suspicious": "",
            "total": "",
            "details": "Non-public IP; VirusTotal lookup skipped."
        }

    request = urllib.request.Request(
        VT_API_URL.format(ip_text),
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": "Cybersecurity-IP-Scanner/1.0"
        }
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        if not stats:
            return {
                "status": "NO REPORT DATA",
                "malicious": "",
                "suspicious": "",
                "total": "",
                "details": "No analysis statistics were returned."
            }

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(value) for value in stats.values())

        if malicious > 0:
            status = "MALICIOUS"
        elif suspicious > 0:
            status = "SUSPICIOUS"
        else:
            status = "NO MALICIOUS DETECTIONS"

        return {
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "total": total,
            "details": f"{malicious} malicious, {suspicious} suspicious out of {total} results."
        }

    except urllib.error.HTTPError as error:
        if error.code == 401:
            details = "Invalid VirusTotal API key."
        elif error.code == 403:
            details = "VirusTotal access denied."
        elif error.code == 404:
            details = "No VirusTotal IP report found."
        elif error.code == 429:
            details = "VirusTotal rate limit reached."
        else:
            details = f"VirusTotal HTTP error: {error.code}"

        return {
            "status": "LOOKUP FAILED",
            "malicious": "",
            "suspicious": "",
            "total": "",
            "details": details
        }

    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
        return {
            "status": "LOOKUP FAILED",
            "malicious": "",
            "suspicious": "",
            "total": "",
            "details": f"VirusTotal lookup failed: {error}"
        }


# =====================================================
# SCAN IP ADDRESS
# =====================================================

def scan_ip(ip_text, loaded_feeds):
    timestamp = get_time()

    try:
        ip_obj = ipaddress.ip_address(ip_text.strip())

        if ip_obj.version != 4:
            raise ValueError("Only IPv4 is supported.")

    except ValueError:
        return {
            "timestamp": timestamp,
            "ip": ip_text,
            "status": "INVALID IP",
            "feed_matches": "None",
            "feed_score": "",
            "vt_status": "NOT CHECKED",
            "vt_malicious": "",
            "vt_suspicious": "",
            "vt_total": "",
            "details": "Enter a valid IPv4 address."
        }

    matches = match_feeds(ip_obj, loaded_feeds)

    if loaded_feeds:
        feed_score = round(
            len(matches) / len(loaded_feeds) * 100
        )
    else:
        feed_score = ""

    vt = check_virustotal(str(ip_obj))

    feed_flagged = bool(matches)
    vt_flagged = vt["status"] in ("MALICIOUS", "SUSPICIOUS")

    if feed_flagged or vt_flagged:
        status = "POTENTIALLY MALICIOUS"
    elif not loaded_feeds and vt["status"] in (
        "NOT CONFIGURED",
        "SKIPPED",
        "LOOKUP FAILED",
        "NO REPORT DATA"
    ):
        status = "CHECK UNAVAILABLE"
    else:
        status = "NO MATCH FOUND"

    return {
        "timestamp": timestamp,
        "ip": str(ip_obj),
        "status": status,
        "feed_matches": ", ".join(matches) if matches else "None",
        "feed_score": feed_score,
        "vt_status": vt["status"],
        "vt_malicious": vt["malicious"],
        "vt_suspicious": vt["suspicious"],
        "vt_total": vt["total"],
        "details": vt["details"]
    }



def display_result(result):
    print("\n" + "=" * 55)
    print(f"IP Address      : {result['ip']}")
    print(f"Final Status    : {result['status']}")
    print(f"Matched Feeds   : {result['feed_matches']}")
    print(f"Feed Match Score: {result['feed_score']}")
    print(f"VirusTotal      : {result['vt_status']}")
    print(f"VT Malicious    : {result['vt_malicious']}")
    print(f"VT Suspicious   : {result['vt_suspicious']}")
    print(f"Details         : {result['details']}")
    print(f"Scan Time       : {result['timestamp']}")
    print("=" * 55)




def save_csv(results):
    new_file = not CSV_FILE.exists() or CSV_FILE.stat().st_size == 0

    with CSV_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=COLUMNS)

        if new_file:
            writer.writeheader()

        for result in results:
            writer.writerow(result)

    print(f"[+] Scan history saved to {CSV_FILE.name}")


def create_csv_attachment(results):
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=COLUMNS)

    writer.writeheader()
    writer.writerows(results)

    return output.getvalue().encode("utf-8-sig")



def create_html_report(results):
    flagged = [
        result for result in results
        if result["status"] == "POTENTIALLY MALICIOUS"
    ]

    table_rows = ""

    for result in flagged:
        table_rows += f"""
        <tr>
          <td style="padding:13px;border-bottom:1px solid #e2e8f0;">
            {html.escape(result['ip'])}
          </td>
          <td style="padding:13px;border-bottom:1px solid #e2e8f0;">
            <span style="background:#fee2e2;color:#991b1b;padding:6px 9px;border-radius:5px;font-weight:bold;">
              POTENTIALLY MALICIOUS
            </span>
          </td>
          <td style="padding:13px;border-bottom:1px solid #e2e8f0;">
            {html.escape(result['feed_matches'])}
          </td>
          <td style="padding:13px;border-bottom:1px solid #e2e8f0;">
            {html.escape(str(result['vt_malicious']))}
          </td>
          <td style="padding:13px;border-bottom:1px solid #e2e8f0;">
            {html.escape(result['timestamp'])}
          </td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <body style="margin:0;padding:0;background:#eef2f7;font-family:Arial,Helvetica,sans-serif;color:#172033;">

      <div style="max-width:950px;margin:25px auto;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #dce3ed;">

        <div style="background:#142b4a;padding:30px;color:white;">
          <div style="font-size:12px;letter-spacing:2px;color:#b8d7ff;">
            SECURITY OPERATIONS CENTER
          </div>
          <h1 style="font-size:27px;margin:12px 0 8px;">
            IP Threat Intelligence Report
          </h1>
          <p style="margin:0;color:#dbeafe;font-size:14px;">
            Automated security monitoring and threat detection
          </p>
        </div>

        <div style="padding:28px;">

          <div style="background:#fff1f2;border-left:5px solid #dc2626;border-radius:7px;padding:18px;margin-bottom:25px;">
            <div style="font-size:12px;font-weight:bold;color:#991b1b;letter-spacing:1px;">
              SECURITY ALERT
            </div>
            <div style="font-size:25px;font-weight:bold;color:#991b1b;margin-top:7px;">
              {len(flagged)} Potential Threat(s) Detected
            </div>
            <p style="font-size:13px;color:#7f1d1d;margin-bottom:0;">
              Review the flagged IP addresses and investigate before taking action.
            </p>
          </div>

          <h2 style="font-size:19px;margin-bottom:13px;">
            Scan Overview
          </h2>

          <table role="presentation" style="width:100%;border-collapse:separate;border-spacing:8px;margin:-8px;margin-bottom:25px;">
            <tr>
              <td style="background:#f1f5f9;padding:19px;border-radius:8px;">
                <div style="font-size:12px;color:#64748b;">IPs Scanned</div>
                <div style="font-size:28px;font-weight:bold;margin-top:7px;">
                  {len(results)}
                </div>
              </td>
              <td style="background:#fff1f2;padding:19px;border-radius:8px;">
                <div style="font-size:12px;color:#9f1239;">Potential Threats</div>
                <div style="font-size:28px;font-weight:bold;color:#be123c;margin-top:7px;">
                  {len(flagged)}
                </div>
              </td>
            </tr>
          </table>

          <h2 style="font-size:19px;margin-bottom:13px;">
            Threat Details
          </h2>

          <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:12px;">
              <thead>
                <tr style="background:#1e3a5f;color:#ffffff;text-align:left;">
                  <th style="padding:13px;">IP Address</th>
                  <th style="padding:13px;">Status</th>
                  <th style="padding:13px;">Matched Feeds</th>
                  <th style="padding:13px;">VT Malicious</th>
                  <th style="padding:13px;">Scan Time</th>
                </tr>
              </thead>
              <tbody>
                {table_rows}
              </tbody>
            </table>
          </div>

          <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:17px;margin-top:25px;">
            <h3 style="font-size:15px;margin-top:0;">Report Information</h3>
            <p style="font-size:13px;line-height:1.8;color:#475569;margin-bottom:0;">
              <b>Generated:</b> {html.escape(get_time())}<br>
              <b>Threat feeds:</b> IPsum, DShield and Abuse.ch Feodo Tracker<br>
              <b>Reputation source:</b> VirusTotal, when configured<br>
              <b>Attachment:</b> Cybersecurity_Threat_Report.csv
            </p>
          </div>

          <p style="font-size:12px;color:#64748b;line-height:1.7;margin-top:22px;">
            Important: A threat-feed match is an investigation indicator, not definitive proof of malicious activity.
            No match does not guarantee that an IP is safe. Feed Match Score is not a probability of maliciousness.
          </p>

        </div>

        <div style="background:#142b4a;color:#dbeafe;padding:18px 28px;font-size:12px;">
          Automated IP Reputation Scanner · Cybersecurity Monitoring
        </div>

      </div>

    </body>
    </html>
    """




def send_gmail_alert(results):
    flagged = [
        result for result in results
        if result["status"] == "POTENTIALLY MALICIOUS"
    ]

    if not flagged:
        print("[i] No flagged IPs. Gmail alert not sent.")
        return

    sender = os.environ.get("GMAIL_SENDER", "").strip()
    recipient = os.environ.get("GMAIL_RECIPIENT", "").strip()
    app_password = os.environ.get("GMAIL_APP_PASSWORD", "").strip()

    if not sender or not recipient or not app_password:
        print("[!] Gmail is not configured.")
        print("[!] Set GMAIL_SENDER, GMAIL_RECIPIENT and GMAIL_APP_PASSWORD.")
        return

    message = EmailMessage()

    message["Subject"] = (
        f"Security Alert: {len(flagged)} Potentially Malicious IP(s)"
    )
    message["From"] = sender
    message["To"] = recipient

    message.set_content(
        f"IP Reputation Scanner detected {len(flagged)} potentially "
        f"malicious IP address(es).\n"
        f"Generated: {get_time()}\n\n"
        "The scan report is attached as a CSV file."
    )

    message.add_alternative(
        create_html_report(results),
        subtype="html"
    )

    csv_data = create_csv_attachment(results)

    message.add_attachment(
        csv_data,
        maintype="text",
        subtype="csv",
        filename="Cybersecurity_Threat_Report.csv"
    )

    try:
        context = ssl.create_default_context()

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=25) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(sender, app_password)
            server.send_message(message)

        print(f"[+] HTML alert sent to {recipient}")
        print("[+] CSV report attached successfully.")

    except (smtplib.SMTPException, OSError) as error:
        print(f"[!] Gmail sending failed: {error}")




def main():
    print("\n" + "=" * 55)
    print("       CYBERSECURITY IP REPUTATION SCANNER")
    print("=" * 55)

    loaded_feeds = load_all_feeds()

    print("\nEnter IPv4 addresses separated by spaces.")
    print("Type 'exit' to close the scanner.")
    print("Example: 8.8.8.8 1.1.1.1\n")

    while True:
        try:
            user_input = input("Enter IP(s): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nScanner closed.")
            break

        if user_input.lower() == "exit":
            print("Scanner closed.")
            break

        if not user_input:
            continue

        ip_list = user_input.split()
        results = []

        for index, ip_text in enumerate(ip_list):
            result = scan_ip(ip_text, loaded_feeds)
            results.append(result)
            display_result(result)

            
            try:
                is_public = ipaddress.ip_address(ip_text).is_global
            except ValueError:
                is_public = False

            if (
                os.environ.get("VT_API_KEY", "").strip()
                and is_public
                and index < len(ip_list) - 1
            ):
                print("[i] Waiting to respect VirusTotal rate limits...")
                time.sleep(16)

        save_csv(results)
        send_gmail_alert(results)

        print("\n[+] Scan batch completed.")
        print(f"[+] CSV history: {CSV_FILE.name}\n")


if __name__ == "__main__":
    main()

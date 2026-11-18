import re
import requests
import pandas as pd
import streamlit as st
from datetime import datetime

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="VulnShield | Vulnerability Defense",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- LIGHT UI ----------------
st.markdown("""
<style>
    .stApp {
        background: #f4f7fb;
        color: #172033;
    }
    [data-testid="stHeader"] {
        background: #f4f7fb;
    }
    [data-testid="stSidebar"] {
        background: #ffffff;
        border-right: 1px solid #dce3ed;
    }
    h1, h2, h3, h4, p, label, span {
        color: #172033;
    }
    .hero {
        background: linear-gradient(120deg, #ffffff, #eaf2ff);
        border: 1px solid #d8e5f5;
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 20px;
    }
    .hero h1 {
        color: #123a70;
        margin-bottom: 6px;
    }
    .hero p {
        color: #40516b;
        margin-bottom: 0;
    }
    .metric-card {
        background: #ffffff;
        border: 1px solid #dce3ed;
        border-radius: 12px;
        padding: 16px;
        min-height: 100px;
        box-shadow: 0 2px 8px rgba(30, 50, 80, 0.04);
    }
    .metric-label {
        color: #5c6b82;
        font-size: 14px;
    }
    .metric-value {
        color: #172033;
        font-size: 28px;
        font-weight: 700;
        margin-top: 5px;
    }
    .info-card {
        background: #ffffff;
        border: 1px solid #dce3ed;
        border-radius: 12px;
        padding: 18px;
        margin: 10px 0;
    }
    .small-muted {
        color: #63728a;
        font-size: 13px;
    }
    div[data-testid="stDataFrame"] {
        background: white;
        border-radius: 10px;
    }
    .stButton button {
        border-radius: 8px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# ---------------- CONSTANTS ----------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ---------------- HELPERS ----------------
def get_severity(cve):
    metrics = cve.get("metrics", {})
    for metric_type in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        entries = metrics.get(metric_type, [])
        if entries:
            data = entries[0].get("cvssData", {})
            severity = data.get("baseSeverity")
            score = data.get("baseScore")
            if severity:
                return severity.upper(), score
            if score is not None:
                if score >= 9:
                    return "CRITICAL", score
                if score >= 7:
                    return "HIGH", score
                if score >= 4:
                    return "MEDIUM", score
                return "LOW", score
    return "UNKNOWN", "N/A"


def get_description(cve):
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "No description available.")
    return "No description available."


def get_references(cve):
    refs = cve.get("references", [])
    return [
        ref.get("url")
        for ref in refs
        if ref.get("url")
    ]


def get_cpes(cve):
    found = []

    def walk(node):
        if not isinstance(node, dict):
            return

        for match in node.get("cpeMatch", []):
            criteria = match.get("criteria")
            if criteria:
                found.append(criteria)

        for child in node.get("children", []):
            walk(child)

        for child in node.get("nodes", []):
            walk(child)

    for config in cve.get("configurations", []):
        walk(config)

    # Remove duplicates while preserving order
    return list(dict.fromkeys(found))


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_kev():
    try:
        response = requests.get(KEV_URL, timeout=20)
        response.raise_for_status()
        data = response.json()
        return {
            item.get("cveID")
            for item in data.get("vulnerabilities", [])
        }
    except Exception:
        return set()


def search_nvd(query, max_results=30):
    params = {"resultsPerPage": max_results}

    if re.fullmatch(r"CVE-\d{4}-\d{4,}", query.strip(), re.IGNORECASE):
        params["cveId"] = query.strip().upper()
    else:
        params["keywordSearch"] = query.strip()

    response = requests.get(NVD_API, params=params, timeout=30)
    response.raise_for_status()
    return response.json().get("vulnerabilities", [])


def build_mitigation(severity, exploited):
    advice = []

    if exploited:
        advice.append(
            "Prioritize this finding: CISA lists it as known exploited. "
            "Confirm exposure and follow the vendor's remediation guidance."
        )

    if severity in ["CRITICAL", "HIGH"]:
        advice.append(
            "Review vendor patch/advisory immediately. If patching is not "
            "currently possible, reduce exposure and apply temporary controls."
        )
    elif severity == "MEDIUM":
        advice.append(
            "Plan remediation based on exposure, affected functionality, "
            "and business impact."
        )
    elif severity == "LOW":
        advice.append(
            "Track remediation and verify whether the affected component "
            "is present and reachable."
        )
    else:
        advice.append(
            "Review the vendor advisory and validate severity for your "
            "specific product/version."
        )

    advice.append(
        "Possible temporary controls: restrict network access, disable the "
        "affected feature if safe, apply secure configuration, monitor "
        "relevant activity, and verify the fix after remediation."
    )
    return advice


# ---------------- HEADER ----------------
st.markdown("""
<div class="hero">
    <h1>🛡️ VulnShield</h1>
    <p>Vulnerability research, risk prioritization, and defensive remediation planning</p>
</div>
""", unsafe_allow_html=True)

st.info(
    "Public-data research dashboard only. Search public vulnerability databases "
    "or enter a software name/CVE ID. This app does not scan systems or networks."
)

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.header("🔎 Vulnerability Search")
    search_query = st.text_input(
        "Software name or CVE ID",
        placeholder="e.g. Apache HTTP Server"
    )
    result_count = st.selectbox(
        "Maximum results",
        [10, 20, 30, 50],
        index=2
    )
    search_button = st.button(
        "Search vulnerabilities",
        type="primary",
        use_container_width=True
    )

    st.divider()
    st.caption("Data sources")
    st.markdown("- [NVD](https://nvd.nist.gov/)")
    st.markdown("- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)")

# ---------------- SESSION STATE ----------------
if "results" not in st.session_state:
    st.session_state.results = []

if "tracker" not in st.session_state:
    st.session_state.tracker = {}

# ---------------- SEARCH ----------------
if search_button:
    if not search_query.strip():
        st.warning("Enter a software name or CVE ID first.")
    else:
        try:
            with st.spinner("Searching public vulnerability databases..."):
                raw_results = search_nvd(search_query, result_count)
                kev_ids = fetch_kev()

                formatted = []
                for item in raw_results:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id", "Unknown")
                    severity, score = get_severity(cve)
                    exploited = cve_id in kev_ids

                    formatted.append({
                        "CVE ID": cve_id,
                        "Severity": severity,
                        "CVSS Score": score,
                        "Known Exploited": "Yes" if exploited else "No",
                        "Description": get_description(cve),
                        "CPEs": get_cpes(cve),
                        "References": get_references(cve),
                        "Mitigation": build_mitigation(severity, exploited)
                    })

                st.session_state.results = formatted

            if not formatted:
                st.warning("No results found. Try another software name.")
            else:
                st.success(f"Found {len(formatted)} vulnerability record(s).")

        except requests.exceptions.RequestException as e:
            st.error(f"Could not reach the public database: {e}")
        except Exception as e:
            st.error(f"Something went wrong: {e}")

# ---------------- RESULTS ----------------
results = st.session_state.results

if results:
    total = len(results)
    critical = sum(1 for r in results if r["Severity"] == "CRITICAL")
    high = sum(1 for r in results if r["Severity"] == "HIGH")
    exploited = sum(1 for r in results if r["Known Exploited"] == "Yes")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">Results</div>'
            f'<div class="metric-value">{total}</div></div>',
            unsafe_allow_html=True
        )
    with c2:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">Critical</div>'
            f'<div class="metric-value">{critical}</div></div>',
            unsafe_allow_html=True
        )
    with c3:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">High</div>'
            f'<div class="metric-value">{high}</div></div>',
            unsafe_allow_html=True
        )
    with c4:
        st.markdown(
            f'<div class="metric-card"><div class="metric-label">Known Exploited</div>'
            f'<div class="metric-value">{exploited}</div></div>',
            unsafe_allow_html=True
        )

    st.subheader("📋 Vulnerability Results")

    table_data = []
    for item in results:
        table_data.append({
            "CVE ID": item["CVE ID"],
            "Severity": item["Severity"],
            "CVSS": item["CVSS Score"],
            "Known Exploited": item["Known Exploited"],
            "Description": item["Description"]
        })

    df = pd.DataFrame(table_data)

    severity_filter = st.multiselect(
        "Filter by severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    )

    filtered = df[df["Severity"].isin(severity_filter)]
    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True
    )

    st.subheader("🔍 Vulnerability Details")

    available_ids = [item["CVE ID"] for item in results]
    selected_id = st.selectbox("Select a vulnerability", available_ids)

    selected = next(
        item for item in results if item["CVE ID"] == selected_id
    )

    st.markdown(
        f"""
        <div class="info-card">
            <h3>{selected["CVE ID"]}</h3>
            <p><b>Severity:</b> {selected["Severity"]} &nbsp; | &nbsp;
            <b>CVSS:</b> {selected["CVSS Score"]} &nbsp; | &nbsp;
            <b>Known Exploited:</b> {selected["Known Exploited"]}</p>
            <p>{selected["Description"]}</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    with st.expander("Affected product/version information (CPE)"):
        if selected["CPEs"]:
            for cpe in selected["CPEs"]:
                st.code(cpe)
        else:
            st.write("No CPE data was provided in this record.")

    with st.expander("Vendor/NVD references"):
        if selected["References"]:
            for url in selected["References"]:
                st.markdown(f"- [{url}]({url})")
        else:
            st.write("No references listed.")

    st.subheader("🧰 Defensive Remediation Guidance")
    for advice in selected["Mitigation"]:
        st.markdown(f"- {advice}")

    st.warning(
        "Important: NVD keyword results may include different product versions. "
        "Confirm the exact affected version and fixed release using the vendor "
        "advisory before deciding that a system is vulnerable or patched."
    )

    # ---------------- TRACKER ----------------
    st.subheader("📝 Remediation Tracker")

    if selected_id not in st.session_state.tracker:
        st.session_state.tracker[selected_id] = {
            "Status": "Not Started",
            "Owner": "",
            "Target Date": "",
            "Notes": ""
        }

    current = st.session_state.tracker[selected_id]

    status = st.selectbox(
        "Remediation status",
        ["Not Started", "Investigating", "Mitigation Applied",
         "Patch Scheduled", "Patched", "Risk Accepted"],
        index=[
            "Not Started", "Investigating", "Mitigation Applied",
            "Patch Scheduled", "Patched", "Risk Accepted"
        ].index(current["Status"]),
        key=f"status_{selected_id}"
    )

    owner = st.text_input(
        "Owner (optional)",
        value=current["Owner"],
        key=f"owner_{selected_id}"
    )

    target_date = st.text_input(
        "Target date (optional, e.g. 2026-11-15)",
        value=current["Target Date"],
        key=f"date_{selected_id}"
    )

    notes = st.text_area(
        "Remediation notes",
        value=current["Notes"],
        key=f"notes_{selected_id}"
    )

    if st.button("Save remediation record", type="primary"):
        st.session_state.tracker[selected_id] = {
            "Status": status,
            "Owner": owner,
            "Target Date": target_date,
            "Notes": notes
        }
        st.success("Remediation record saved for this session.")

    # ---------------- IN-PAGE REPORT ----------------
    st.subheader("📊 Remediation Report")

    report_rows = []
    for item in results:
        record = st.session_state.tracker.get(
            item["CVE ID"],
            {
                "Status": "Not Started",
                "Owner": "",
                "Target Date": "",
                "Notes": ""
            }
        )

        report_rows.append({
            "CVE ID": item["CVE ID"],
            "Severity": item["Severity"],
            "Known Exploited": item["Known Exploited"],
            "Status": record["Status"],
            "Owner": record["Owner"],
            "Target Date": record["Target Date"],
            "Notes": record["Notes"]
        })

    report_df = pd.DataFrame(report_rows)
    st.dataframe(report_df, use_container_width=True, hide_index=True)

    patched_count = sum(
        1 for row in report_rows if row["Status"] == "Patched"
    )
    st.caption(
        f"Patched: {patched_count} of {len(report_rows)} records. "
        "Tracker data is temporary and resets when the app restarts."
    )

else:
    st.markdown("""
    <div class="info-card">
        <h3>Welcome to VulnShield</h3>
        <p>Search a software name to review public vulnerability records.</p>
        <p><b>Try:</b> Apache HTTP Server, OpenSSH, or Log4j.</p>
        <p class="small-muted">
        Use public database information for learning. Do not treat keyword
        search results as confirmation that a specific installed version
        is vulnerable.
        </p>
    </div>
    """, unsafe_allow_html=True)

st.divider()
st.caption(
    f"VulnShield • Public vulnerability research • Updated view: "
    f"{datetime.now().strftime('%Y-%m-%d %H:%M')}"
)

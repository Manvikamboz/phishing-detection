import streamlit as st
import requests
import os
import time
import plotly.graph_objects as go
import plotly.express as px

API_URL = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(page_title="Phishing Detector", page_icon="🛡️", layout="wide")
st.title("🛡️ Phishing Detection System")
st.markdown("Enter a URL below to analyze it for phishing threats.")

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚡ Cache Logs")
    if st.button("Refresh Cache", use_container_width=True):
        try:
            logs = requests.get(f"{API_URL}/cache/logs", timeout=5).json()
            if logs:
                for entry in logs:
                    color = {"phishing": "🔴", "suspicious": "🟡", "benign": "🟢"}.get(entry["label"], "⚪")
                    st.markdown(f"{color} **{entry['label'].upper()}** — Score: `{entry['score']}`")
                    st.caption(f"🔗 {entry['url']}")
                    st.caption(f"🕒 {entry['cached_at']} | ⏳ {entry['expires_in']}")
                    st.divider()
            else:
                st.info("No cached results yet.")
        except Exception as e:
            st.error(f"Could not fetch cache: {e}")
    if st.button("🗑️ Clear Cache", use_container_width=True):
        try:
            requests.delete(f"{API_URL}/cache", timeout=5)
            st.success("Cache cleared!")
        except Exception as e:
            st.error(f"Could not clear cache: {e}")

# ── Input ─────────────────────────────────────────────────────────────────────
url_input = st.text_input("🔗 URL", placeholder="https://example.com")

if st.button("Analyze", use_container_width=True):
    if not url_input.strip():
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Analyzing URL"):
            try:
                t0 = time.time()
                resp = requests.post(f"{API_URL}/predict", json={"url": url_input.strip()}, timeout=180)
                resp.raise_for_status()
                data = resp.json()
                elapsed = round(time.time() - t0, 2)
            except Exception as e:
                st.error(f"Failed to reach API: {e}")
                st.stop()

        label  = data["label"]
        score  = data["score"]
        color  = {"phishing": "🔴", "suspicious": "🟡", "benign": "🟢"}.get(label, "⚪")

        # ── Top summary row ───────────────────────────────────────────────────
        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            st.markdown(f"## {color} `{label.upper()}`")
            st.caption(f"⏱ Analysis took {elapsed}s {'(cached)' if data.get('cached') else ''}")
        with col2:
            st.metric("Risk Score", f"{score} / 100")
        with col3:
            models_used = data.get("ml", {}).get("models_used", 1)
            st.metric("Models Used", models_used)

        st.progress(score / 100)

        # ── Gauge ─────────────────────────────────────────────────────────────
        gauge_color = "red" if label == "phishing" else "orange" if label == "suspicious" else "green"
        gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            gauge={
                "axis": {"range": [0, 100]},
                "bar":  {"color": gauge_color},
                "steps": [
                    {"range": [0,  35],  "color": "#d4edda"},
                    {"range": [35, 65],  "color": "#fff3cd"},
                    {"range": [65, 100], "color": "#f8d7da"},
                ],
                "threshold": {"line": {"color": gauge_color, "width": 4}, "thickness": 0.75, "value": score},
            },
            title={"text": "Overall Phishing Risk Score"},
        ))
        gauge.update_layout(height=260, margin=dict(t=50, b=0, l=20, r=20))
        st.plotly_chart(gauge, use_container_width=True)

        # ── Source score breakdown (color-coded) ──────────────────────────────
        source_scores = data.get("source_scores", {})
        if source_scores:
            st.subheader("📊 Detection Source Breakdown")

            # A source score > 50 means it contributed toward phishing
            # A source score < 50 means it contributed toward legitimate
            src_colors = []
            src_labels_annotated = []
            for src, val in source_scores.items():
                if val >= 65:
                    src_colors.append("red")
                    src_labels_annotated.append(f"{src} ⚠️")
                elif val >= 45:
                    src_colors.append("orange")
                    src_labels_annotated.append(f"{src} ⚡")
                else:
                    src_colors.append("green")
                    src_labels_annotated.append(f"{src} ✅")

            src_fig = go.Figure(go.Bar(
                x=src_labels_annotated,
                y=list(source_scores.values()),
                marker_color=src_colors,
                text=[f"{v}" for v in source_scores.values()],
                textposition="outside",
            ))
            src_fig.add_hline(y=65, line_dash="dash", line_color="red",
                              annotation_text="Phishing threshold (65)", annotation_position="top left")
            src_fig.add_hline(y=35, line_dash="dash", line_color="green",
                              annotation_text="Benign threshold (35)", annotation_position="bottom left")
            src_fig.update_layout(
                title="Each source's contribution",
                yaxis=dict(range=[0, 110], title="Threat Score (0=clean, 100=threat)"),
                xaxis_title="Detection Source",
                height=380, margin=dict(t=60, b=0),
                showlegend=False,
            )
            st.plotly_chart(src_fig, use_container_width=True)

        # ── Reasons — with consistent context ────────────────────────────────
        st.subheader("📋 Why this verdict?")
        reasons = data.get("reasons", [])
        if reasons:
            for r in reasons:
                if "🚨" in r or "OVERRIDE" in r:
                    st.error(r)
                elif any(w in r.lower() for w in ["phishing", "malicious", "flagged", "suspicious",
                                                   "threat", "tor", "proxy", "malware", "new", "hidden"]):
                    st.warning(f"⚠️ {r}")
                else:
                    st.success(f"✅ {r}")
        else:
            if label == "benign":
                st.success("✅ No threats detected — all signals indicate this is a legitimate URL.")
            else:
                st.info("No specific reasons returned.")

        # ── Verdict explanation ───────────────────────────────────────────────
        st.subheader("🧠 Verdict Explanation")
        if label == "benign":
            st.success(
                f"**Score {score}/100 → BENIGN.** "
                "All detection sources (ML model, VirusTotal, URL heuristics, IPQualityScore) "
                "returned clean or low-risk signals. The domain appears legitimate."
            )
        elif label == "suspicious":
            st.warning(
                f"**Score {score}/100 → SUSPICIOUS.** "
                "Some signals are elevated but not conclusive. "
                "Proceed with caution — do not enter credentials on this site."
            )
        else:
            st.error(
                f"**Score {score}/100 → PHISHING.** "
                "Multiple detection sources flagged this URL as malicious. "
                "Do NOT visit or enter any information on this site."
            )

        st.divider()

        # ── ML Model Details ──────────────────────────────────────────────────
        with st.expander("🤖 ML Model Details"):
            ml = data.get("ml", {})
            mc1, mc2 = st.columns(2)
            with mc1:
                st.metric("ML Label", ml.get("label", "N/A").upper())
                st.metric("ML Confidence", f"{ml.get('confidence', 0):.1f}%")
                st.metric("Models Pooled", ml.get("models_used", 1))
            with mc2:
                probs = ml.get("probabilities", {})
                if probs:
                    prob_fig = go.Figure(go.Bar(
                        x=list(probs.keys()),
                        y=[round(v * 100, 1) for v in probs.values()],
                        marker_color=["green" if k == "legitimate" else "red" for k in probs.keys()],
                        text=[f"{round(v*100,1)}%" for v in probs.values()],
                        textposition="outside",
                    ))
                    prob_fig.update_layout(
                        title="ML Model Class Probabilities",
                        yaxis=dict(range=[0, 115], title="%"),
                        height=260, margin=dict(t=40, b=0),
                        showlegend=False,
                    )
                    st.plotly_chart(prob_fig, use_container_width=True)

            # Explain ML result vs final verdict consistency
            ml_label = ml.get("label", "")
            if ml_label != label and label == "benign":
                st.info(
                    f"ℹ️ The ML model predicted **{ml_label}** ({ml.get('confidence',0):.1f}% confidence) "
                    f"but the final verdict is **BENIGN**. "
                    "This is because the ML model's prediction was overridden by strong clean signals "
                    "from VirusTotal, IPQualityScore, and/or the trusted domain list. "
                    "The ML model alone can be biased when domain age / page rank features are unavailable."
                )
            elif ml_label == label:
                st.success(f"✅ ML model agrees with the final verdict: **{label.upper()}**")

        # ── VirusTotal ────────────────────────────────────────────────────────
        with st.expander("🌐 VirusTotal Report"):
            vt = data.get("virustotal", {})
            if vt.get("error"):
                st.warning(f"VirusTotal error: {vt['error']}")
            else:
                vc1, vc2, vc3, vc4 = st.columns(4)
                vc1.metric("🔴 Malicious",  vt.get("malicious", 0))
                vc2.metric("🟠 Suspicious", vt.get("suspicious", 0))
                vc3.metric("🟢 Harmless",   vt.get("harmless", 0))
                vc4.metric("⚪ Undetected", vt.get("undetected", 0))

                total = sum([vt.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected"]])
                vt_fig = go.Figure(go.Bar(
                    x=["Malicious", "Suspicious", "Harmless", "Undetected"],
                    y=[vt.get("malicious", 0), vt.get("suspicious", 0),
                       vt.get("harmless", 0), vt.get("undetected", 0)],
                    marker_color=["red", "orange", "green", "gray"],
                    text=[vt.get("malicious", 0), vt.get("suspicious", 0),
                          vt.get("harmless", 0), vt.get("undetected", 0)],
                    textposition="outside",
                ))
                vt_fig.update_layout(
                    title=f"VirusTotal — {total} engines scanned",
                    yaxis_title="Engine Count",
                    height=300, margin=dict(t=40, b=0), showlegend=False,
                )
                st.plotly_chart(vt_fig, use_container_width=True)

                mal = vt.get("malicious", 0)
                if mal == 0:
                    st.success("✅ No engines flagged this URL as malicious.")
                elif mal < 3:
                    st.warning(f"⚠️ {mal} engine(s) flagged as malicious — low confidence, may be a false positive.")
                else:
                    st.error(f"🚨 {mal} engines flagged as malicious — high confidence phishing/malware.")

        # ── AbuseIPDB ─────────────────────────────────────────────────────────
        with st.expander("🔍 AbuseIPDB Report"):
            abuse = data.get("abuseipdb", {})
            if abuse.get("error"):
                st.warning(f"AbuseIPDB error: {abuse['error']}")
            else:
                ac1, ac2, ac3 = st.columns(3)
                ac1.metric("Abuse Score",    f"{abuse.get('abuse_score', 0)}%")
                ac2.metric("Total Reports",  abuse.get("total_reports", 0))
                ac3.metric("Country",        abuse.get("country", "N/A"))
                st.caption(f"IP: `{abuse.get('ip','N/A')}` | ISP: {abuse.get('isp','N/A')} | TOR: {abuse.get('is_tor', False)}")
                if abuse.get("cdn_masked"):
                    st.info(f"ℹ️ IP is behind a CDN ({abuse.get('isp')}) — abuse score may be 0 even for phishing sites.")
                abuse_score = abuse.get("abuse_score", 0)
                abuse_fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=abuse_score,
                    gauge={
                        "axis": {"range": [0, 100]},
                        "bar": {"color": "red" if abuse_score > 50 else "orange" if abuse_score > 20 else "green"},
                        "steps": [
                            {"range": [0, 20],  "color": "#d4edda"},
                            {"range": [20, 50], "color": "#fff3cd"},
                            {"range": [50, 100],"color": "#f8d7da"},
                        ],
                    },
                    title={"text": "IP Abuse Confidence Score"},
                ))
                abuse_fig.update_layout(height=220, margin=dict(t=40, b=0, l=20, r=20))
                st.plotly_chart(abuse_fig, use_container_width=True)

        # ── IPQualityScore ────────────────────────────────────────────────────
        with st.expander("🛡️ IPQualityScore Report"):
            ipqs = data.get("ipqualityscore", {})
            if not ipqs or ipqs.get("error"):
                st.warning(f"IPQualityScore: {ipqs.get('error', 'No data') if ipqs else 'No data returned'}")
            else:
                qc1, qc2, qc3 = st.columns(3)
                qc1.metric("Fraud Score",   ipqs.get("fraud_score", 0))
                qc2.metric("Domain Rank",   ipqs.get("domain_rank", "N/A"))
                qc3.metric("Domain Age",    f"{ipqs.get('domain_age_days', -1)} days" if ipqs.get('domain_age_days', -1) >= 0 else "Unknown")

                flags = {
                    "Phishing":  ipqs.get("phishing", False),
                    "Malware":   ipqs.get("malware", False),
                    "Suspicious":ipqs.get("suspicious", False),
                    "Proxy/VPN": ipqs.get("is_proxy", False) or ipqs.get("is_vpn", False),
                    "Bot":       ipqs.get("is_bot", False),
                }
                flag_colors = ["red" if v else "green" for v in flags.values()]
                flag_fig = go.Figure(go.Bar(
                    x=list(flags.keys()),
                    y=[1 if v else 0 for v in flags.values()],
                    marker_color=flag_colors,
                    text=["YES ⚠️" if v else "NO ✅" for v in flags.values()],
                    textposition="outside",
                ))
                flag_fig.update_layout(
                    title="IPQualityScore Threat Flags",
                    yaxis=dict(range=[0, 1.5], showticklabels=False),
                    height=280, margin=dict(t=40, b=0), showlegend=False,
                )
                st.plotly_chart(flag_fig, use_container_width=True)

                fraud = ipqs.get("fraud_score", 0)
                if ipqs.get("phishing"):
                    st.error("🚨 IPQualityScore confirmed this URL as a PHISHING site.")
                elif ipqs.get("malware"):
                    st.error("🚨 IPQualityScore confirmed MALWARE on this URL.")
                elif fraud >= 75:
                    st.warning(f"⚠️ High fraud score ({fraud}) — URL is suspicious.")
                elif fraud < 20:
                    st.success(f"✅ Low fraud score ({fraud}) — URL appears clean.")

        # ── IPStack Geolocation ───────────────────────────────────────────────
        with st.expander("🌍 IPStack Geolocation & Threat"):
            ip = data.get("ipstack", {})
            if not ip or ip.get("error"):
                st.warning(f"IPStack: {ip.get('error', 'No data') if ip else 'No data'}")
            else:
                ic1, ic2, ic3 = st.columns(3)
                ic1.metric("Country", ip.get("country_name", "N/A"))
                ic2.metric("City",    ip.get("city", "N/A"))
                ic3.metric("IP",      ip.get("ip", "N/A"))

                threat_flags = {
                    "TOR Node":  ip.get("is_tor", False),
                    "Proxy":     ip.get("is_proxy", False),
                    "Anonymous": ip.get("is_anonymous", False),
                    "Attacker":  ip.get("is_attacker", False),
                }
                any_threat = any(threat_flags.values())
                if any_threat:
                    st.error("🚨 Threat flags detected on this IP address.")
                else:
                    st.success("✅ No threat flags on this IP address.")

                if ip.get("latitude") is not None and ip.get("longitude") is not None:
                    marker_color = ("red"    if ip.get("is_attacker") else
                                    "orange" if (ip.get("is_tor") or ip.get("is_proxy")) else
                                    "yellow" if ip.get("is_anonymous") else "green")
                    world_map = go.Figure(go.Scattergeo(
                        lat=[ip["latitude"]], lon=[ip["longitude"]],
                        mode="markers+text",
                        marker=dict(size=16, color=marker_color, line=dict(width=2, color="white")),
                        text=[f"  {ip.get('city')}, {ip.get('country_name')}"],
                        textposition="top right",
                        hovertext=[f"IP: {ip.get('ip')}<br>Location: {ip.get('city')}, {ip.get('country_name')}<br>"
                                   f"TOR: {ip.get('is_tor')} | Proxy: {ip.get('is_proxy')}"],
                        hoverinfo="text",
                    ))
                    world_map.update_layout(
                        geo=dict(
                            projection_type="equirectangular",
                            showland=True, landcolor="#e8f4e8",
                            showocean=True, oceancolor="#cce5ff",
                            showcoastlines=True, coastlinecolor="#888888",
                            showcountries=True, countrycolor="#aaaaaa",
                            showframe=True, framecolor="#888888",
                            lonaxis=dict(range=[-180, 180]),
                            lataxis=dict(range=[-90, 90]),
                        ),
                        title=f"IP Location — {ip.get('city')}, {ip.get('country_name')} {'🚨 THREAT' if any_threat else '✅ Clean'}",
                        height=420, margin=dict(t=50, b=0, l=0, r=0),
                    )
                    st.plotly_chart(world_map, use_container_width=True)

        # ── HTML Features ─────────────────────────────────────────────────────
        with st.expander("🧱 HTML Analysis"):
            hf = data.get("html_features", {})
            if not hf or hf.get("error"):
                st.warning(f"HTML scraper: {hf.get('error', 'No data') if hf else 'No data'}")
            else:
                hc1, hc2, hc3, hc4 = st.columns(4)
                hc1.metric("Login Form",      "Yes ⚠️" if hf.get("has_login_form") else "No ✅")
                hc2.metric("Password Field",  "Yes ⚠️" if hf.get("has_password_field") else "No ✅")
                hc3.metric("iFrames",         hf.get("iframe_count", 0))
                hc4.metric("External Scripts",hf.get("external_script_count", 0))

                numeric_hf = {k: v for k, v in hf.items()
                              if isinstance(v, (int, float)) and k != "error"}
                if numeric_hf:
                    # Color bars: known risky features in red, others in steelblue
                    risky = {"has_login_form", "has_password_field", "iframe_count",
                             "hidden_element_count", "form_action_empty", "external_script_count"}
                    hf_colors = ["red" if k in risky and v > 0 else "steelblue"
                                 for k, v in numeric_hf.items()]
                    hf_fig = go.Figure(go.Bar(
                        x=list(numeric_hf.keys()),
                        y=list(numeric_hf.values()),
                        marker_color=hf_colors,
                        text=list(numeric_hf.values()),
                        textposition="outside",
                    ))
                    hf_fig.update_layout(
                        title="HTML Feature Values — red bars indicate risky signals",
                        xaxis_tickangle=-35,
                        height=340, margin=dict(t=40, b=80), showlegend=False,
                    )
                    st.plotly_chart(hf_fig, use_container_width=True)

                if hf.get("has_login_form") and hf.get("has_password_field"):
                    st.warning("⚠️ This page has a login form with a password field — common in credential-harvesting phishing pages.")
                if hf.get("iframe_count", 0) > 2:
                    st.warning(f"⚠️ {hf['iframe_count']} iframes detected — phishing pages often embed hidden iframes.")
                if hf.get("external_script_count", 0) > 10:
                    st.warning(f"⚠️ {hf['external_script_count']} external scripts — unusually high, may indicate malicious injection.")
                if not hf.get("has_login_form") and not hf.get("has_password_field") and hf.get("iframe_count", 0) <= 2:
                    st.success("✅ No suspicious HTML patterns detected.")

        # ── FetchSERP ─────────────────────────────────────────────────────────
        with st.expander("🔎 FetchSERP Domain Intelligence"):
            fs = data.get("fetchserp", {})
            if not fs or fs.get("error"):
                st.info(f"FetchSERP: {fs.get('error', 'No data') if fs else 'No data — API key not configured yet.'}")
            else:
                fc1, fc2, fc3 = st.columns(3)
                fc1.metric("Domain Age",    f"{fs.get('domain_age_days', 'N/A')} days")
                fc2.metric("Google Indexed", "Yes ✅" if fs.get("google_index") else "No ⚠️")
                fc3.metric("Page Rank",      fs.get("page_rank", "N/A"))



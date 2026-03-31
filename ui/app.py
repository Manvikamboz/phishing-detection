import streamlit as st
import requests
import os
import time
import plotly.graph_objects as go
import plotly.express as px

API_URL = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(page_title="Phishing Detector", page_icon="🛡️", layout="centered")

st.title("🛡️ AI-Based Phishing Detection System")
st.markdown("Enter a URL below to analyze it for phishing threats.")

# Sidebar cache viewer
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
                    st.caption(f"🕒 {entry['cached_at']} | ⏳ expires in {entry['expires_in']}")
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

url_input = st.text_input("🔗 URL", placeholder="https://example.com")

if st.button("Analyze", use_container_width=True):
    if not url_input.strip():
        st.warning("Please enter a URL.")
    else:
        with st.spinner("Analyzing URL..."):
            try:
                t0 = time.time()
                resp = requests.post(f"{API_URL}/predict", json={"url": url_input.strip()}, timeout=60)
                resp.raise_for_status()
                data = resp.json()
                elapsed = round(time.time() - t0, 2)
            except Exception as e:
                st.error(f"Failed to reach API: {e}")
                st.stop()

        label = data["label"]
        score = data["score"]

        # Header row
        color = {"phishing": "🔴", "suspicious": "🟡", "benign": "🟢"}.get(label, "⚪")
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown(f"## {color} Result: `{label.upper()}`")
        with col2:
            if data.get("cached"):
                st.info("⚡ Cached")
            st.caption(f"⏱ {elapsed}s")

        st.metric("Risk Score", f"{score} / 100")
        st.progress(score / 100)

        # Risk gauge
        gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "red" if label == "phishing" else "orange" if label == "suspicious" else "green"},
                "steps": [
                    {"range": [0, 40],  "color": "#d4edda"},
                    {"range": [40, 70], "color": "#fff3cd"},
                    {"range": [70, 100],"color": "#f8d7da"},
                ],
            },
            title={"text": "Risk Score"},
        ))
        gauge.update_layout(height=250, margin=dict(t=40, b=0, l=20, r=20))
        st.plotly_chart(gauge, use_container_width=True)

        # Source score breakdown
        source_scores = data.get("source_scores", {})
        if source_scores:
            src_fig = px.bar(
                x=list(source_scores.keys()),
                y=list(source_scores.values()),
                color=list(source_scores.keys()),
                title="Score Contribution by Source",
                labels={"x": "Source", "y": "Points"},
                text_auto=True,
            )
            src_fig.update_layout(showlegend=False, height=300, margin=dict(t=40, b=0))
            st.plotly_chart(src_fig, use_container_width=True)

        st.subheader("📋 Reasons")
        for r in data["reasons"]:
            st.markdown(f"- {r}")

        with st.expander("🤖 ML Model Details"):
            st.json(data["ml"])

        with st.expander("🌐 VirusTotal Report"):
            st.json(data["virustotal"])
            vt = data["virustotal"]
            if isinstance(vt, dict) and "malicious" in vt:
                vt_labels = ["Malicious", "Suspicious", "Harmless", "Undetected"]
                vt_values = [vt.get("malicious", 0), vt.get("suspicious", 0),
                             vt.get("harmless", 0), vt.get("undetected", 0)]
                vt_fig = px.bar(x=vt_labels, y=vt_values, color=vt_labels,
                                color_discrete_map={"Malicious": "red", "Suspicious": "orange",
                                                    "Harmless": "green", "Undetected": "gray"},
                                labels={"x": "Verdict", "y": "Engines"}, title="VirusTotal Engine Results")
                vt_fig.update_layout(showlegend=False, height=300, margin=dict(t=40, b=0))
                st.plotly_chart(vt_fig, use_container_width=True)

        with st.expander("🔍 AbuseIPDB Report"):
            st.json(data["abuseipdb"])

        with st.expander("🌍 IPStack Geolocation & Threat"):
            ip = data.get("ipstack", {})
            st.json(ip)
            if ip and not ip.get("error") and ip.get("latitude") is not None and ip.get("longitude") is not None:
                is_threat = ip.get("is_attacker") or ip.get("is_tor") or ip.get("is_proxy") or ip.get("is_anonymous")
                marker_color = ("red" if ip.get("is_attacker") else
                                "orange" if (ip.get("is_tor") or ip.get("is_proxy")) else
                                "yellow" if ip.get("is_anonymous") else "green")
                tooltip = (f"IP: {ip.get('ip')}<br>"
                           f"Location: {ip.get('city')}, {ip.get('region')}, {ip.get('country')}<br>"
                           f"TOR: {ip.get('is_tor')} | Proxy: {ip.get('is_proxy')}<br>"
                           f"Anonymous: {ip.get('is_anonymous')} | Attacker: {ip.get('is_attacker')}")
                world_map = go.Figure(go.Scattergeo(
                    lat=[ip["latitude"]], lon=[ip["longitude"]],
                    mode="markers+text",
                    marker=dict(size=16, color=marker_color, symbol="circle", line=dict(width=2, color="white")),
                    text=[f"  {ip.get('city')}, {ip.get('country')}"],
                    textposition="top right",
                    hovertext=[tooltip], hoverinfo="text",
                ))
                world_map.update_layout(
                    geo=dict(
                        projection_type="mercator",
                        showland=True, landcolor="#e8f4e8",
                        showocean=True, oceancolor="#cce5ff",
                        showcoastlines=True, coastlinecolor="#888888",
                        showcountries=True, countrycolor="#aaaaaa",
                        showframe=False,
                        lonaxis=dict(range=[ip["longitude"] - 8, ip["longitude"] + 8]),
                        lataxis=dict(range=[ip["latitude"] - 6, ip["latitude"] + 6]),
                    ),
                    title=dict(text=f"IP Location — {ip.get('city')}, {ip.get('region')}, {ip.get('country')} "
                                    f"{'🚨 THREAT' if is_threat else '✅ Clean'}"),
                    height=450, margin=dict(t=50, b=0, l=0, r=0),
                )
                st.plotly_chart(world_map, use_container_width=True)

                threat_flags = {"TOR": ip.get("is_tor", False), "Proxy": ip.get("is_proxy", False),
                                "Anonymous": ip.get("is_anonymous", False), "Attacker": ip.get("is_attacker", False)}
                flag_fig = px.bar(x=list(threat_flags.keys()), y=[int(v) for v in threat_flags.values()],
                                  color=list(threat_flags.keys()), title="IPStack Threat Flags",
                                  labels={"x": "Flag", "y": "Detected"})
                flag_fig.update_layout(showlegend=False, height=250, margin=dict(t=40, b=0))
                st.plotly_chart(flag_fig, use_container_width=True)

        with st.expander("🧱 HTML Features"):
            st.json(data["html_features"])
            hf = data["html_features"]
            if isinstance(hf, dict):
                numeric = {k: v for k, v in hf.items() if isinstance(v, (int, float))}
                if numeric:
                    hf_fig = px.bar(x=list(numeric.keys()), y=list(numeric.values()),
                                    labels={"x": "Feature", "y": "Value"}, title="HTML Feature Values")
                    hf_fig.update_layout(height=300, margin=dict(t=40, b=0))
                    st.plotly_chart(hf_fig, use_container_width=True)

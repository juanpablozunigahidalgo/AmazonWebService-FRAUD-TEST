# app.py
# Streamlit app: AWS Fraud Prevention — Analytical Dashboard
# Save this file in same folder as aws_fraud_case.sqlite and run: streamlit run app.py

import streamlit as st
import pandas as pd
import numpy as np
import sqlite3
import os
from datetime import timedelta
import plotly.express as px
import math
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest

# Use relative DB path (same folder)
DB_PATH = os.path.join(os.path.dirname(__file__), "aws_fraud_case.sqlite")

st.set_page_config(page_title="AWS Fraud Analytics", layout="wide")
st.title("AWS Fraud Prevention — Interactive Analytics Prototype")

# ---------- Helpers ----------
def read_sql_df(sql):
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql(sql, conn)
    finally:
        conn.close()
    return df

@st.cache_data(ttl=600)
def load_tables():
    # load all tables in a safe way
    conn = sqlite3.connect(DB_PATH)
    try:
        tables = {}
        for t in ["users","logins","ec2_activity","payments","ip_reputation","security_findings"]:
            try:
                tables[t] = pd.read_sql(f"SELECT * FROM {t}", conn)
            except Exception:
                tables[t] = pd.DataFrame()
        # normalize timestamps
        for k in ["users","logins","ec2_activity","payments","security_findings"]:
            if k in tables and not tables[k].empty:
                for c in tables[k].columns:
                    if c.endswith("_ts") or c.endswith("ts"):
                        tables[k][c] = pd.to_datetime(tables[k][c], errors="coerce")
        return tables
    finally:
        conn.close()

def compute_account_signals(logins, iprep, days):
    # compute account-level signals in last N days (Python side for flexibility)
    if logins.empty:
        return pd.DataFrame()
    last_ts = logins['event_ts'].max()
    if pd.isna(last_ts):
        return pd.DataFrame()
    window_start = last_ts - pd.Timedelta(days=days)
    lastN = logins[logins['event_ts'] >= window_start].copy()
    hist = logins[logins['event_ts'] < window_start].copy()
    lastN = lastN.merge(iprep[['ip','risk_score','is_tor']], how='left', on='ip')
    agg = lastN.groupby('account_id').agg(
        fails = ('result', lambda s: (s=='FAIL').sum()),
        total = ('result', 'count'),
        mfa_count = ('mfa_used', lambda s: s.fillna(0).astype(int).sum()),
        device_count = ('device_id', lambda s: s.dropna().nunique()),
        tor_count = ('is_tor', lambda s: s.fillna(0).astype(int).sum()),
        high_risk_count = ('risk_score', lambda s: (s.fillna(0)>=80).sum())
    ).reset_index()
    # new_country_rate
    hist_countries = hist.groupby('account_id')['country_iso'].unique().to_dict()
    def new_country_rate(acc):
        last_countries = set(lastN[lastN['account_id']==acc]['country_iso'].dropna().unique())
        prev = set(hist_countries.get(acc, []))
        if len(last_countries)==0:
            return 0.0
        new = len([c for c in last_countries if c not in prev])
        return new/len(last_countries)
    agg['new_country_rate'] = agg['account_id'].apply(new_country_rate)
    agg['failed_login_rate'] = agg.apply(lambda r: r['fails']/r['total'] if r['total']>0 else 0.0, axis=1)
    agg['mfa_rate'] = agg.apply(lambda r: r['mfa_count']/r['total'] if r['total']>0 else 0.0, axis=1)
    agg['tor_login_count'] = agg['tor_count']
    agg['high_risk_ip_share'] = agg.apply(lambda r: r['high_risk_count']/r['total'] if r['total']>0 else 0.0, axis=1)
    # composite score (tunable weights)
    agg['composite'] = 0.4*agg['failed_login_rate'] + 0.3*agg['new_country_rate'] + 0.2*(agg['tor_login_count']>0).astype(int) + 0.1*agg['high_risk_ip_share']
    return agg

def detect_compromise_patterns(logins, iprep, ec2, risk_threshold=80, run_threshold=4, region_threshold=2, window_hours=24):
    if logins.empty or ec2.empty:
        return pd.DataFrame()
    merged = logins.merge(iprep, how='left', on='ip')
    risky = merged[(merged['result']=='FAIL') & (merged['risk_score']>=risk_threshold)].copy()
    if risky.empty:
        return pd.DataFrame()
    ec2 = ec2.copy()
    ec2['event_ts'] = pd.to_datetime(ec2['event_ts'], errors='coerce')
    rows = []
    for _, r in risky.iterrows():
        acc = r['account_id']; t0 = r['event_ts']
        if pd.isna(t0): continue
        t_end = t0 + pd.Timedelta(hours=window_hours)
        sub = ec2[(ec2['account_id']==acc) & (ec2['event_ts']>=t0) & (ec2['event_ts']<=t_end) & (ec2['action']=='RUN_INSTANCES')]
        run_cnt = sub.shape[0]
        region_cnt = sub['region'].nunique()
        if run_cnt >= run_threshold and region_cnt >= region_threshold:
            rows.append({'account_id':acc, 'trigger_ts':t0, 'run_count_24h':run_cnt, 'region_count_24h':region_cnt})
    return pd.DataFrame(rows)

def two_prop_z(x1, n1, x2, n2):
    p1 = x1/n1 if n1>0 else 0.0
    p2 = x2/n2 if n2>0 else 0.0
    pool = (x1+x2)/(n1+n2) if (n1+n2)>0 else 0.0
    denom = math.sqrt(pool*(1-pool)*(1/n1 + 1/n2)) if (n1>0 and n2>0) else 1.0
    z = (p1-p2)/denom if denom>0 else 0.0
    cdf = 0.5 * (1 + math.erf(abs(z)/math.sqrt(2)))
    pval = 2*(1 - cdf)
    return z, pval, p1, p2

# ---------- Load data ----------
tables = load_tables()
users = tables.get('users', pd.DataFrame())
logins = tables.get('logins', pd.DataFrame())
ec2 = tables.get('ec2_activity', pd.DataFrame())
payments = tables.get('payments', pd.DataFrame())
iprep = tables.get('ip_reputation', pd.DataFrame())
findings = tables.get('security_findings', pd.DataFrame())

# ---------- Sidebar controls ----------
st.sidebar.header("Controls")
days = st.sidebar.slider("Recent window (days)", 7, 90, 14)
risk_threshold = st.sidebar.slider("IP risk threshold", 50, 100, 80, 5)
run_threshold = st.sidebar.slider("RUN_INSTANCES threshold", 1, 20, 4)
region_threshold = st.sidebar.slider("Distinct region threshold", 1, 5, 2)
cluster_k = st.sidebar.slider("Clustering K", 2, 8, 3)
iso_contam = st.sidebar.slider("IsolationForest contamination", 0.01, 0.5, 0.05, 0.01)

# ---------- KPIs ----------
st.subheader("Dataset summary")
c1,c2,c3,c4 = st.columns(4)
c1.metric("Users", f"{users.shape[0]:,}")
c2.metric("Login events", f"{logins.shape[0]:,}")
c3.metric("EC2 events", f"{ec2.shape[0]:,}")
c4.metric("Payments", f"{payments.shape[0]:,}")

# ---------- Time series ----------
st.markdown("### Daily failed login rate")
try:
    df_ts = read_sql_df("""
        SELECT date(event_ts) AS day,
               SUM(CASE WHEN result='FAIL' THEN 1 ELSE 0 END)*1.0/COUNT(*) AS fail_rate,
               COUNT(*) AS total_logins
        FROM logins
        GROUP BY day
        ORDER BY day;
    """)
    fig = px.line(df_ts, x='day', y='fail_rate', title='Daily failed login rate', markers=True)
    st.plotly_chart(fig, use_container_width=True)
except Exception as e:
    st.error("Time series error: " + str(e))

# ---------- Account signals ----------
st.markdown("### Account-level signals (computed)")
signals = compute_account_signals(logins, iprep, days)
if signals.empty:
    st.info("No signals (check timestamps or data).")
else:
    st.dataframe(signals.sort_values('composite', ascending=False).head(50))

# ---------- Clustering & anomalies ----------
st.markdown("### Clustering & anomaly detection")
if not signals.empty:
    feat = signals[['failed_login_rate','new_country_rate','tor_login_count','high_risk_ip_share']].fillna(0)
    scaler = StandardScaler(); X = scaler.fit_transform(feat)
    try:
        kmeans = KMeans(n_clusters=cluster_k, random_state=42, n_init=10)
        labels = kmeans.fit_predict(X)
        signals['cluster'] = labels
    except Exception as e:
        signals['cluster'] = 0
        st.warning("KMeans failed: " + str(e))
    try:
        iso = IsolationForest(contamination=iso_contam, random_state=42)
        anoms = iso.fit_predict(X)
        signals['anomaly'] = anoms  # -1 anomaly, 1 normal
        signals['anomaly_flag'] = signals['anomaly'].apply(lambda x: 1 if x==-1 else 0)
    except Exception as e:
        signals['anomaly_flag'] = 0
        st.warning("IsolationForest failed: " + str(e))

    st.write(signals.groupby('cluster')['anomaly_flag'].sum().reset_index().rename(columns={'anomaly_flag':'anomaly_count'}))
    figc = px.scatter(signals, x='failed_login_rate', y='new_country_rate', color='cluster', symbol='anomaly_flag',
                      size=(signals['tor_login_count']+1), hover_data=['account_id','composite'],
                      title='Clusters & anomalies (size=tor_count)')
    st.plotly_chart(figc, use_container_width=True)
else:
    st.info("No signals available for clustering.")

# ---------- Compromise detection ----------
st.markdown("### Compromise pattern detection (risky fail -> EC2 burst)")
compromised = detect_compromise_patterns(logins, iprep, ec2,
                                         risk_threshold=risk_threshold,
                                         run_threshold=run_threshold,
                                         region_threshold=region_threshold)
st.write(f"Triggers found: {len(compromised)}")
if not compromised.empty:
    st.dataframe(compromised.sort_values('trigger_ts', ascending=False).head(50))
else:
    st.info("No compromise triggers found under current thresholds.")

# ---------- Payments correlation ----------
st.markdown("### Payments correlation: flagged vs baseline")
if compromised.empty or payments.empty:
    st.info("Need both compromised triggers and payments data to compute correlation.")
else:
    flagged = list(compromised['account_id'].unique())
    baseline_n = payments['account_id'].nunique()
    baseline_bad_accounts = payments[payments['status'].isin(['CHARGEBACK','DECLINED'])]['account_id'].drop_duplicates().shape[0]
    flagged_bad_accounts = payments[(payments['account_id'].isin(flagged)) & (payments['status'].isin(['CHARGEBACK','DECLINED']))]['account_id'].drop_duplicates().shape[0]
    if baseline_n>0 and len(flagged)>0:
        p_baseline = baseline_bad_accounts / baseline_n
        p_flagged = flagged_bad_accounts / len(flagged)
        z, pval, _, _ = two_prop_z(flagged_bad_accounts, len(flagged), baseline_bad_accounts, baseline_n)
        st.markdown(f"Baseline bad payment rate: **{p_baseline:.2%}** | Flagged cohort: **{p_flagged:.2%}**")
        st.markdown(f"Two-proportion z-test: z={z:.2f}, p-value={pval:.4f}")
    else:
        st.info("Not enough data to compute payment correlation.")

# ---------- Drilldown ----------
st.markdown("### Account drilldown (inspect events)")
accs = signals['account_id'].sort_values().unique().tolist() if not signals.empty else users['account_id'].sort_values().unique().tolist()
acc_selected = st.selectbox("Select an account_id", options=accs[:1000])  # limit listing to avoid huge lists
if acc_selected:
    st.write("Login events (last 100):")
    q = f"SELECT * FROM logins WHERE account_id = '{acc_selected}' ORDER BY event_ts DESC LIMIT 100"
    df_acc_logins = read_sql_df(q)
    st.dataframe(df_acc_logins)
    st.write("EC2 events (last 100):")
    st.dataframe(read_sql_df(f"SELECT * FROM ec2_activity WHERE account_id = '{acc_selected}' ORDER BY event_ts DESC LIMIT 100"))
    st.write("Payments (last 100):")
    st.dataframe(read_sql_df(f"SELECT * FROM payments WHERE account_id = '{acc_selected}' ORDER BY payment_ts DESC LIMIT 100"))

# ---------- Exports ----------
st.markdown("### Export CSVs")
if not signals.empty:
    st.download_button("Download account signals CSV", signals.to_csv(index=False), file_name="account_signals.csv", mime="text/csv")
if not compromised.empty:
    st.download_button("Download compromise triggers CSV", compromised.to_csv(index=False), file_name="compromised_triggers.csv", mime="text/csv")

st.caption("Prototype - For production: add authentication, logging, secure DB access, and tests.")

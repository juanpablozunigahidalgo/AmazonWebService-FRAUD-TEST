# AmazonWebService-FRAUD-TEST

On 02-10-2025. I got an interview with AMAZON. Berlin. AWS. The position was about Fraud analyst (SEE position description on position-description.txt).
In order to show capabilities. I created a theoretical analytical case on fraud. Which involves a DATABASE (DATA SETS). And from that I developed the case to show. 
Bellow is the "Problem Definition"

# SECTION 1 PROBLEM 
# Problem definition — AWS Fraud Prevention (Mock Case)

**Author:** AWS Business Engineer - > Juan Pablo Zuniga Hidalgo
**Date:** 2025-10-01  
**Audience:** Candidate for AWS Fraud Analyst II (applied exercise + interview)

## Executive summary / business context
Cloud accounts are frequently targeted by fraudsters who attempt credential stuffing, account takeover, or post-compromise resource abuse (spinning up cloud instances to mine crypto or run malware). This mock case provides a compact, realistic dataset capturing these domains:

- **Logins**: successful/failed login events with IP, device, country, MFA flag  
- **IP reputation**: IP risk score, ASN, TOR flag  
- **EC2 activity**: instance actions and region — used to detect post-login bursts  
- **Payments**: charges, amounts, statuses (used as a proxy for fraud losses)  
- **Security findings**: small labeled set to approximate confirmed compromises

Your task as a Business Analyst is to **monitor trends, build explainable signals and detection logic, and propose actionable mitigation rules** so the global security team can triage and reduce fraud losses while minimizing false positives for legitimate customers.

---

## Business objective
1. Identify new and emerging patterns of compromise and triage high-priority accounts quickly.  
2. Provide explainable, operational signals that scale and integrate with automated mitigation (MFA challenge, rate limit, throttle EC2 provisioning, case open).  
3. Demonstrate a reproducible workflow: SQL → feature engineering → analytics → rule proposals → impact estimate.

---

## Constraints & assumptions
- You will work offline against the supplied `aws_fraud_case.sqlite` (SQLite). The dataset is synthetic but engineered to reflect real signals.
- No external enrichment is required; use only the supplied tables.
- Operational rules should minimize customer friction (prefer step-up authentication over account deletion).
- You have ~60 minutes in a live interview to query, reason, and present.

---

## Success criteria (how you will be evaluated)
- **Technical correctness**: accurate queries & transformations, efficient use of joins/CTEs.  
- **Signal quality**: clear, explainable features that map to fraud behaviors.  
- **Operational value**: rules that balance precision vs. recall with plausible alert volumes.  
- **Communication**: concise executive summary and triage playbook.

---

## Deliverables (what we expect from you)
1. Key queries (SQL) to compute baseline metrics: daily fail rate, top failing IPs, distribution of IP risk.  
2. Table or artifact with account-level signals (last 14 days): failed_login_rate, new_country_rate, mfa_rate, tor_login_count, device_churn, high_risk_ip_share, composite score.  
3. Detection query for **risky fail → EC2 burst** (24h window) and a list of triggering account IDs.  
4. Simple statistical check: correlate flagged accounts with payment failures (chargebacks/declines) and report significance (two-proportion z-test or Fisher exact if small).  
5. 2–3 operational mitigation rules: rule definition, expected daily alerts (estimate), proxy precision using `security_findings` or payments as a label.  
6. Executive summary: 6–8 bullet points and playbook steps for containment & longer-term modelization.

---

## Interview instruction to the candidate
- You have access to the SQLite DB and the Streamlit app demo (optional). Use SQL to extract signals and Python to run small analyses.  
- Explain assumptions you make about thresholds and why.  
- If you cannot compute a metric accurately due to data constraints, state the limitation and propose how you would fill the gap.

---

## Who wrote this problem
Juan Pablo Zuniga Hidalgo — AWS Business Engineer (juanpablozunigahidalgo@aws.example)  
> *This is a mock exercise created for interview practice. The dataset is synthetic. Use it to practice your analytical process and storytelling skills.*

---

## Next steps for candidate
1. Fork or clone this repo.  
2. Run the provided Streamlit demo or run SQL in DBeaver/sqlite3.  
3. Produce a short `SOLUTION_SUMMARY.md` covering the deliverables above and push a branch `yourname/aws-fraud-solution`.  
4. Create a PR and include screenshots / CSV exports for evidence.

Good luck — think like a fraudster, and then think like an investigator.


# STEEP 2 SOLUTION EXPLAINED 
This app reads a local database of synthetic AWS-style events (logins, IP reputation, EC2 activity, payments, and security findings). It computes account-level risk signals such as failed-login rate, new-country activity, TOR usage and device churn; looks for a specific dangerous pattern where a risky failed login is followed by a burst of EC2 RUN_INSTANCES across multiple regions; groups accounts into clusters and flags anomalies; runs a basic statistical test to see whether flagged accounts have worse payment outcomes; and provides interactive charts and drilldowns so analysts can triage and export evidence. How the app is organized (big picture) Load the data from a local SQLite file. Compute signals for each account (recent failed-login rate, device churn, new-country rate, TOR usage, etc.). 
Detect compromise patterns: find cases where a risky failed login is followed soon after by many RUN_INSTANCES actions in different regions. Analyze and visualize: produce a time series of failed logins, list top suspicious IPs, show clusters of high-risk accounts and anomaly flags. Correlate with payments: test whether flagged accounts are more likely to have chargebacks or declines. Provide operational outputs: create lists and CSVs for investigators and enable interactive per-account drilldowns. Key building blocks explained for non-programmers Reading the database (read_sql_df and load_tables) 
What it does: opens the local database file and reads each table (users, logins, ec2_activity, ip_reputation, payments, security_findings) into memory. Why it's important: this is where the app gets the raw evidence (login rows, IP risk data, EC2 actions). If the database file is not in the right place, nothing else works. Analogy: like loading several spreadsheets into an analyst’s workbook. Building account signals (compute_account_signals) What it does: for each account, the app computes several measures over a recent window (default 14 days): failed_login_rate: fraction of login attempts that failed. Higher values suggest brute-force or credential stuffing. mfa_rate: fraction of logins using multi-factor authentication. Low MFA adoption plus high failure rate is risky. device_count: number of unique devices seen recently. Many devices may indicate attacker devices or credential sharing. new_country_rate: fraction of recent login countries that were not seen historically for that account. This flags geographic anomalies. tor_login_count: number of logins from TOR or anonymizing networks. high_risk_ip_share: share of logins that came from IPs rated as high risk. composite: a single, tunable score that combines these signals into a ranking. 

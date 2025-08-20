# ��� Prescriptive DGA Detector: From Black Box to Playbook

This project demonstrates an end-to-end security analytics workflow integrating:

* **H2O AutoML** for domain classification (legit vs. DGA)
* **Explainable AI (XAI)** to justify predictions using entropy and length features
* **Google Generative AI (Gemini)** to auto-generate tailored incident response playbooks

## ��� Overview

Cybersecurity teams face growing threats from malware using Domain Generation Algorithms (DGAs) to evade detection. This tool helps defenders rapidly:

1. **Classify** suspicious domains as legit or DGA
2. **Explain** model reasoning using interpretable features
3. **Prescribe** concrete SOC actions using GenAI-generated playbooks

---

## ��� How It Works (Pipeline Architecture)

```
User Input (domain)
   └──> [Feature Engineering: length, entropy]
         └──> [H2O AutoML Model Prediction (MOJO)]
               └──> [SHAP-style Explanation (XAI)]
                     └──> [GenAI Prompting]
                           └──> ��� Incident Response Playbook
```

---

## ��� Installation

```bash
git clone https://github.com/yourusername/prescriptive-dga-detector
cd prescriptive-dga-detector
python -m venv venv
source venv/bin/activate  # Or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Ensure your **Google Generative AI API key** is exported:

```bash
export GOOGLE_API_KEY="your-api-key"
```

---

## ��� Model Training

```bash
python 1_train_and_export.py
```

* Trains an H2O AutoML model using entropy/length features
* Saves the best MOJO model to `model/DGA_Leader.zip`

---

## ��� Domain Analysis (Main Script)

```bash
python 2_analyze_domain.py --domain kq3v9z7j1x5f8g2h.info
```

**Output Includes:**

* Domain prediction (legit or DGA)
* XAI explanation summary
* Gemini-generated incident response playbook

---

## ��� Project Structure

```
prescriptive-dga-detector/
├── 1_train_and_export.py       # AutoML model training
├── 2_analyze_domain.py         # Command-line analyzer
├── genai_prescriptions.py      # Gemini API bridge
├── model/DGA_Leader.zip        # Exported MOJO model
├── data/dga_dataset_train.csv  # Training dataset (generated)
├── README.md                   # Project overview
├── TESTING.md                  # Manual test walkthroughs
└── .github/workflows/lint.yml  # GitHub Actions for code linting
```

---

 ��� Technologies Used

* Python 3.10+
* [H2O AutoML](https://docs.h2o.ai/h2o/latest-stable/h2o-docs/automl.html)
* SHAP-style explanations (manually crafted logic)
* [Google Generative AI](https://ai.google.dev/)



## ✅ Example Output (Truncated)

CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain kq3v9z7j1x5f8g2h.info
[+] Input domain: kq3v9z7j1x5f8g2h.info
[+] Computed features → Length: 21, Entropy: 4.3
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_1d4j56
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 36.0%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'kq3v9z7j1x5f8g2h.info'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 36.0% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 4.3 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 21 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:**  [Auto-generated ID]
**Date/Time:** [Auto-generated Timestamp]
**Alert Source:** DGA Detection Model
**Severity:** Medium (Adjustable based on context and further investigation)

**1. Initial Triage & Validation:**

* **Action:** Verify the alert.  Cross-reference the domain ('kq3v9z7j1x5f8g2h.info') against known threat intelligence feeds (e.g., VirusTotal, ThreatCrowd). Check for existing entries in your SIEM/SOAR system related to this domain.
* **Expected Outcome:** Confirmation of the domain's existence and identification of any malicious activity associated with it.  VirusTotal/ThreatCrowd reports should be included in the incident report.
* **Responsible Party:** SOC Analyst Level 1
* **Time Estimate:** 15-30 minutes

**2. Domain Investigation:**

* **Action:** Perform a WHOIS lookup to identify the registrant information and registration date. Investigate the domain's DNS records (A, AAAA, MX, etc.) to identify any associated IP addresses and potential hosting providers. Check for any SSL certificates associated with the domain.
* **Expected Outcome:**  Identification of the domain's registrant, hosting provider, and associated IP addresses.  Determination of the domain's purpose (if any).
* **Responsible Party:** SOC Analyst Level 1
* **Time Estimate:** 30-60 minutes

**3. Network Traffic Analysis:**

* **Action:** If the domain resolves to an IP address, analyze network traffic logs (firewall, IDS/IPS, proxy logs) for any communication involving this IP address or domain.  Pay close attention to connections originating from internal systems.
* **Expected Outcome:** Identification of any compromised systems communicating with the malicious domain.  Determination of the volume and type of traffic.
* **Responsible Party:** SOC Analyst Level 2
* **Time Estimate:** 60-120 minutes

**4. System Isolation & Remediation:**

* **Action:** If compromised systems are identified, isolate them from the network to prevent further compromise.  Initiate malware analysis and remediation steps on affected systems. This may involve deploying endpoint detection and response (EDR) tools.
* **Expected Outcome:**  Compromised systems isolated and secured. Malware removed and vulnerabilities patched.
* **Responsible Party:** SOC Analyst Level 2/Incident Response Team
* **Time Estimate:** Variable, depending on the extent of compromise

**5. Threat Hunting & Containment:**

* **Action:** Expand the investigation to identify any other domains generated by the same DGA algorithm.  Utilize threat intelligence platforms and sandboxing technologies to analyze any associated malware.  Consider using YARA rules to detect similar domains.
* **Expected Outcome:**  Identification and mitigation of any additional threats associated with the DGA.
* **Responsible Party:** SOC Analyst Level 3/Threat Hunter
* **Time Estimate:** Variable

**6. Post-Incident Activities:**

* **Action:** Document all findings in a detailed incident report.  Update security controls and processes to prevent similar incidents in the future.  Consider implementing DGA detection and prevention tools at a broader level.  Communicate findings to relevant stakeholders.      
* **Expected Outcome:**  Complete incident report, improved security posture, and informed stakeholders.
* **Responsible Party:** SOC Analyst Level 1/Incident Response Team
* **Time Estimate:** Variable


**AI Model Confidence Note:** The AI model flagged this domain with 36% confidence, which is relatively low.  While the high entropy and length values are suspicious, manual validation and further investigation are crucial to confirm malicious intent.  The playbook emphasizes thorough investigation before undertaking drastic actions.

**Escalation Criteria:**  Escalate to higher-level SOC analysts or the Incident Response Team if:
* Multiple systems are affected.
* Critical systems are compromised.
* Significant data exfiltration is suspected.
* The investigation exceeds allocated resources.
Closing connection _sid_8518 at exit
H2O session _sid_8518 closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain amazon.com
[+] Input domain: amazon.com
[+] Computed features → Length: 10, Entropy: 2.72
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_086xyk
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: LEGIT (Confidence: 99.5%)
[+] Domain appears legitimate. No playbook generated.
Closing connection _sid_9459 at exit
H2O session _sid_9459 closed.
(venv)
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain lksdjf9347xxp.biz
^C
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain lksdjf9347xxp.biz
[+] Input domain: lksdjf9347xxp.biz
[+] Computed features → Length: 17, Entropy: 3.97
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_j96uyu
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 27.9%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'lksdjf9347xxp.biz'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 27.9% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.97 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 17 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generated ID]
**Date/Time:** [Timestamp]
**Alert Source:** DGA Detection Model
**Severity:** Medium (initially, can escalate)

**1. Initial Assessment & Triage:**

* **Verify Alert:** Confirm the alert details (domain: 'lksdjf9347xxp.biz') and associated metadata from the DGA detection system. Review the raw logs leading to the alert.
* **Model Confidence:** Note the model's confidence level (27.9%). While not overwhelmingly high, the contributing factors warrant investigation.
* **Threat Intelligence Check:** Query threat intelligence platforms (e.g., VirusTotal, MISP, ThreatConnect) for the domain 'lksdjf9347xxp.biz'.  Look for existing malicious classifications, reports, or associations.
* **Internal System Check:**  Determine if any internal systems have contacted or attempted to contact this domain. Review DNS logs, firewall logs, and network traffic logs (if available).

**2. Investigation & Containment:**

* **Domain Resolution:** Perform a DNS lookup for the domain to resolve its IP address(es).  Note the IP address(es) and their geolocation.
* **IP Address Investigation:** Investigate the resolved IP address(es) using threat intelligence platforms.  Check for known malicious activity associated with these IPs.
* **Network Segmentation (if applicable):** If the domain is found to be malicious and internal systems have contacted it, consider isolating affected systems from the network to prevent further compromise.
* **Traffic Analysis:** Analyze network traffic associated with the domain and resolved IP addresses to identify potential compromised systems or data exfiltration attempts.  Pay close attention to unusual outbound connections.
* **Malware Analysis (if applicable):** If malware is suspected, collect samples (if possible and safe) for analysis in a sandboxed environment.

**3. Remediation & Recovery:**

* **Block the Domain:** Implement a block rule in the firewall and DNS to prevent access to 'lksdjf9347xxp.biz' and any associated IP addresses.
* **Remediate Compromised Systems:** If internal systems are compromised, follow established incident response procedures for malware removal and system hardening (including patching and password resets).
* **Log Analysis:** Thoroughly review logs to identify the scope of the compromise and potential impact.
* **User Notification:** Inform affected users (if any) of the incident and any necessary actions.

**4. Post-Incident Activities:**

* **Reporting:** Generate a detailed incident report summarizing the findings, actions taken, and lessons learned.
* **Model Feedback:** Provide feedback to the DGA detection model team regarding the alert, focusing on the model’s confidence level and the accuracy of the alert. This will help improve the model's performance over time.
* **Security Awareness Training:** If the incident involves user interaction (e.g., phishing), consider providing additional security awareness training to users.
* **Update Procedures:** Review existing security controls and procedures to determine if any improvements are necessary to prevent similar incidents in the future.


**Escalation Criteria:**

* High confidence level from the DGA detection model.
* Identification of malicious activity associated with the domain/IP address.
* Evidence of data exfiltration or system compromise.
* Impact to critical business functions.


**Note:** This playbook provides a general framework. Specific actions may need to be adjusted depending on the organization's security infrastructure, policies, and the severity of the incident.  Always prioritize data protection and minimizing business disruption.
Closing connection _sid_b7e8 at exit
H2O session _sid_b7e8 closed.
(venv)
CSD@User MINGW64 ~/prescriptive-dga-detector
$ [200~python 2_analyze_domain.py --domain google.com
bash: [200~python: command not found
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain t7xg9q12znd8vh.net
[+] Input domain: t7xg9q12znd8vh.net
[+] Computed features → Length: 18, Entropy: 3.95
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_dtx2rt
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 29.6%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 't7xg9q12znd8vh.net'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 29.6% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.95 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 18 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generate ID]
**Date/Time:** [Auto-generate Timestamp]
**Alert Source:** DGA Detection Model
**Alert Severity:** Medium (Confidence: 29.6%)

**1. Initial Triage & Validation:**

* **Action:** Verify the domain's existence using a DNS lookup tool (e.g., `nslookup`, `dig`).  Note the IP address(es) returned, if any.
* **Action:** Check if the IP address(es) are associated with known malicious infrastructure using threat intelligence feeds (e.g., VirusTotal, MISP, ThreatCrowd).
* **Action:** Review the domain registration information (registrar, registrant details, creation date) using WHOIS lookup tools.  Look for suspicious patterns (e.g., anonymous registration, privacy protection).
* **Action:** Assess the confidence level (29.6%) in light of other indicators. Low confidence requires careful consideration before escalating.

**2. Investigation & Analysis:**

* **Action:** Analyze network traffic related to the suspected DGA domain. If the domain resolves to an IP address, examine network flows involving that IP using a network monitoring tool (e.g., SIEM, packet capture analysis). Look for unusual outbound connections, high volume of traffic, or connections to known malicious IPs/networks.
* **Action:** Investigate if any internal systems attempted to resolve or connect to this domain.  This involves analyzing logs from DNS servers, web browsers, and other relevant applications. Identify affected systems/users.
* **Action:** If the domain is linked to a specific malware family, review the associated threat intelligence to understand potential impact and further actions required.

**3. Containment & Eradication:**

* **Action:** If the investigation confirms malicious activity, block the domain at the network perimeter (firewall, DNS filtering).
* **Action:** If affected systems are identified, isolate them from the network to prevent further compromise.
* **Action:** Initiate malware analysis of affected systems. Consider using sandbox environments for safe analysis.
* **Action:** If malware is found, implement a remediation strategy, which might involve removing the malware, restoring from backups, or reinstalling operating systems.


**4. Post-Incident Activity:**

* **Action:** Document the entire incident response process, including all actions taken, findings, and remediation steps.
* **Action:** Update threat intelligence feeds with the identified malicious domain and IP address(es).
* **Action:** Review security controls and identify any gaps that allowed the DGA domain to be accessed.  This could include weaknesses in DNS security, lack of robust endpoint protection, or insufficient threat intelligence coverage.
* **Action:** Implement necessary changes to prevent similar incidents in the future. This might involve enhancing firewall rules, deploying better endpoint detection and response (EDR) solutions, or improving security awareness training for users.


**5. Escalation:**

Escalate the incident to a higher level if:

* The confidence level increases significantly.
* The impact on the organization is substantial.
* The investigation reveals a widespread compromise.


**Model Explanation Context:**

The high entropy (3.95) and length (18) values suggest a randomly generated domain name, a common characteristic of DGAs.  However, the relatively low confidence (29.6%) indicates that other features might be mitigating this initial assessment.  Thorough investigation is crucial to determine the actual malicious nature of the domain.  Further investigation should be guided by other correlated alerts or events.
Closing connection _sid_82c6 at exit
H2O session _sid_82c6 closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain unknownhost123.biz
[+] Input domain: unknownhost123.biz
[+] Computed features → Length: 18, Entropy: 3.79
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_r0cz09
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 27.1%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'unknownhost123.biz'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 27.1% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.79 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 18 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generate ID]
**Date/Time:** [Timestamp]
**Alert Source:** DGA Detection Model
**Alert Type:** Potential DGA Domain Detected

**1. Initial Assessment & Triage (Analyst Level 1)**

* **Action 1:** Verify the alert details. Confirm the domain ("unknownhost123.biz") and the associated confidence level (27.1%).  Note that this is a relatively low confidence score; further investigation is critical.
* **Action 2:** Check if the domain is already known (e.g., VirusTotal, ThreatCrowd, passive DNS databases). If it's flagged malicious, proceed to Section 2. If not, continue to Action 3.
* **Action 3:** Review the model's explanation.  Note the high entropy (3.79) and length (18) values.  This suggests a randomly generated domain name, a characteristic of DGAs.  However, the low confidence score warrants caution.
* **Action 4:**  Investigate the source of the alert.  Where was this domain observed?  (e.g., DNS logs, network traffic, endpoint logs). Identify affected systems or users if possible.
* **Action 5:** Assign a severity level based on the context.  Given the low confidence and lack of immediate confirmation, initially assign a low to medium severity. This might be upgraded later.

**2. Investigation & Confirmation (Analyst Level 2)**

* **Action 6:** Perform deeper analysis using additional tools.  Investigate the domain's DNS records (A, AAAA, MX, TXT). Check for unusual or nonexistent records.
* **Action 7:** Analyze network traffic associated with the domain.  Look for unusual communication patterns (e.g., high volume, unusual ports, encrypted traffic).  If the domain is resolving, consider capturing network traffic for deeper malware analysis.
* **Action 8:** Analyze endpoint logs from systems that contacted the domain (if identified in Action 4). Look for suspicious activity related to the domain.
* **Action 9:** Consult threat intelligence feeds for similar domains or patterns.  Search for related malware families or campaigns.
* **Action 10:** If evidence strongly suggests malicious activity (e.g., communication with known C2 servers, malware downloads), escalate to Section 3.  If not, document findings and update the alert severity.

**3. Containment & Remediation (Analyst Level 3)**

* **Action 11:**  If the domain is confirmed as malicious, block access to it at the network perimeter (firewall, proxy) and on affected endpoints (host-based firewall).
* **Action 12:** Initiate malware analysis of any downloaded files associated with the domain.
* **Action 13:** Investigate the infection vector. How did the compromised system(s) come into contact with the DGA?
* **Action 14:** Perform affected system remediation. This includes removing malware, updating antivirus software, patching vulnerabilities, and restoring from backups if necessary.    
* **Action 15:** Monitor for further activity from the domain or related domains.


**4. Post-Incident Activity**

* **Action 16:** Document all findings and actions taken in a comprehensive incident report.
* **Action 17:** Update the DGA detection model with the new data (if applicable).
* **Action 18:** Implement preventative measures to reduce the likelihood of future DGA-related incidents.  This might include improving DNS security, enhancing endpoint detection and response capabilities, and improving employee security awareness training.
* **Action 19:** Conduct a post-incident review to identify areas for improvement in the incident response process.


**Escalation:**  Escalate to senior security personnel or management if the incident is severe, involves critical systems, or requires significant resources.


**Note:** The low confidence score (27.1%) highlights the importance of thorough investigation.  Do not solely rely on the DGA model's output;  use it as one piece of evidence in a broader investigation.  Always correlate findings from multiple sources before taking action.
Closing connection _sid_a89c at exit
H2O session _sid_a89c closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain google.com
[+] Input domain: google.com
[+] Computed features → Length: 10, Entropy: 2.65
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_uuvtja
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: LEGIT (Confidence: 99.6%)
[+] Domain appears legitimate. No playbook generated.
Closing connection _sid_b469 at exit
H2O session _sid_b469 closed.
(venv)CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain kq3v9z7j1x5f8g2h.info
[+] Input domain: kq3v9z7j1x5f8g2h.info
[+] Computed features → Length: 21, Entropy: 4.3
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_1d4j56
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 36.0%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'kq3v9z7j1x5f8g2h.info'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 36.0% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 4.3 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 21 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:**  [Auto-generated ID]
**Date/Time:** [Auto-generated Timestamp]
**Alert Source:** DGA Detection Model
**Severity:** Medium (Adjustable based on context and further investigation)

**1. Initial Triage & Validation:**

* **Action:** Verify the alert.  Cross-reference the domain ('kq3v9z7j1x5f8g2h.info') against known threat intelligence feeds (e.g., VirusTotal, ThreatCrowd). Check for existing entries in your SIEM/SOAR system related to this domain.
* **Expected Outcome:** Confirmation of the domain's existence and identification of any malicious activity associated with it.  VirusTotal/ThreatCrowd reports should be included in the incident report.
* **Responsible Party:** SOC Analyst Level 1
* **Time Estimate:** 15-30 minutes

**2. Domain Investigation:**

* **Action:** Perform a WHOIS lookup to identify the registrant information and registration date. Investigate the domain's DNS records (A, AAAA, MX, etc.) to identify any associated IP addresses and potential hosting providers. Check for any SSL certificates associated with the domain.
* **Expected Outcome:**  Identification of the domain's registrant, hosting provider, and associated IP addresses.  Determination of the domain's purpose (if any).
* **Responsible Party:** SOC Analyst Level 1
* **Time Estimate:** 30-60 minutes

**3. Network Traffic Analysis:**

* **Action:** If the domain resolves to an IP address, analyze network traffic logs (firewall, IDS/IPS, proxy logs) for any communication involving this IP address or domain.  Pay close attention to connections originating from internal systems.
* **Expected Outcome:** Identification of any compromised systems communicating with the malicious domain.  Determination of the volume and type of traffic.
* **Responsible Party:** SOC Analyst Level 2
* **Time Estimate:** 60-120 minutes

**4. System Isolation & Remediation:**

* **Action:** If compromised systems are identified, isolate them from the network to prevent further compromise.  Initiate malware analysis and remediation steps on affected systems. This may involve deploying endpoint detection and response (EDR) tools.
* **Expected Outcome:**  Compromised systems isolated and secured. Malware removed and vulnerabilities patched.
* **Responsible Party:** SOC Analyst Level 2/Incident Response Team
* **Time Estimate:** Variable, depending on the extent of compromise

**5. Threat Hunting & Containment:**

* **Action:** Expand the investigation to identify any other domains generated by the same DGA algorithm.  Utilize threat intelligence platforms and sandboxing technologies to analyze any associated malware.  Consider using YARA rules to detect similar domains.
* **Expected Outcome:**  Identification and mitigation of any additional threats associated with the DGA.
* **Responsible Party:** SOC Analyst Level 3/Threat Hunter
* **Time Estimate:** Variable

**6. Post-Incident Activities:**

* **Action:** Document all findings in a detailed incident report.  Update security controls and processes to prevent similar incidents in the future.  Consider implementing DGA detection and prevention tools at a broader level.  Communicate findings to relevant stakeholders.      
* **Expected Outcome:**  Complete incident report, improved security posture, and informed stakeholders.
* **Responsible Party:** SOC Analyst Level 1/Incident Response Team
* **Time Estimate:** Variable


**AI Model Confidence Note:** The AI model flagged this domain with 36% confidence, which is relatively low.  While the high entropy and length values are suspicious, manual validation and further investigation are crucial to confirm malicious intent.  The playbook emphasizes thorough investigation before undertaking drastic actions.

**Escalation Criteria:**  Escalate to higher-level SOC analysts or the Incident Response Team if:
* Multiple systems are affected.
* Critical systems are compromised.
* Significant data exfiltration is suspected.
* The investigation exceeds allocated resources.
Closing connection _sid_8518 at exit
H2O session _sid_8518 closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain amazon.com
[+] Input domain: amazon.com
[+] Computed features → Length: 10, Entropy: 2.72
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_086xyk
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: LEGIT (Confidence: 99.5%)
[+] Domain appears legitimate. No playbook generated.
Closing connection _sid_9459 at exit
H2O session _sid_9459 closed.
(venv)
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain lksdjf9347xxp.biz
^C
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain lksdjf9347xxp.biz
[+] Input domain: lksdjf9347xxp.biz
[+] Computed features → Length: 17, Entropy: 3.97
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_j96uyu
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 27.9%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'lksdjf9347xxp.biz'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 27.9% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.97 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 17 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generated ID]
**Date/Time:** [Timestamp]
**Alert Source:** DGA Detection Model
**Severity:** Medium (initially, can escalate)

**1. Initial Assessment & Triage:**

* **Verify Alert:** Confirm the alert details (domain: 'lksdjf9347xxp.biz') and associated metadata from the DGA detection system. Review the raw logs leading to the alert.
* **Model Confidence:** Note the model's confidence level (27.9%). While not overwhelmingly high, the contributing factors warrant investigation.
* **Threat Intelligence Check:** Query threat intelligence platforms (e.g., VirusTotal, MISP, ThreatConnect) for the domain 'lksdjf9347xxp.biz'.  Look for existing malicious classifications, reports, or associations.
* **Internal System Check:**  Determine if any internal systems have contacted or attempted to contact this domain. Review DNS logs, firewall logs, and network traffic logs (if available).

**2. Investigation & Containment:**

* **Domain Resolution:** Perform a DNS lookup for the domain to resolve its IP address(es).  Note the IP address(es) and their geolocation.
* **IP Address Investigation:** Investigate the resolved IP address(es) using threat intelligence platforms.  Check for known malicious activity associated with these IPs.
* **Network Segmentation (if applicable):** If the domain is found to be malicious and internal systems have contacted it, consider isolating affected systems from the network to prevent further compromise.
* **Traffic Analysis:** Analyze network traffic associated with the domain and resolved IP addresses to identify potential compromised systems or data exfiltration attempts.  Pay close attention to unusual outbound connections.
* **Malware Analysis (if applicable):** If malware is suspected, collect samples (if possible and safe) for analysis in a sandboxed environment.

**3. Remediation & Recovery:**

* **Block the Domain:** Implement a block rule in the firewall and DNS to prevent access to 'lksdjf9347xxp.biz' and any associated IP addresses.
* **Remediate Compromised Systems:** If internal systems are compromised, follow established incident response procedures for malware removal and system hardening (including patching and password resets).
* **Log Analysis:** Thoroughly review logs to identify the scope of the compromise and potential impact.
* **User Notification:** Inform affected users (if any) of the incident and any necessary actions.

**4. Post-Incident Activities:**

* **Reporting:** Generate a detailed incident report summarizing the findings, actions taken, and lessons learned.
* **Model Feedback:** Provide feedback to the DGA detection model team regarding the alert, focusing on the model’s confidence level and the accuracy of the alert. This will help improve the model's performance over time.
* **Security Awareness Training:** If the incident involves user interaction (e.g., phishing), consider providing additional security awareness training to users.
* **Update Procedures:** Review existing security controls and procedures to determine if any improvements are necessary to prevent similar incidents in the future.


**Escalation Criteria:**

* High confidence level from the DGA detection model.
* Identification of malicious activity associated with the domain/IP address.
* Evidence of data exfiltration or system compromise.
* Impact to critical business functions.


**Note:** This playbook provides a general framework. Specific actions may need to be adjusted depending on the organization's security infrastructure, policies, and the severity of the incident.  Always prioritize data protection and minimizing business disruption.
Closing connection _sid_b7e8 at exit
H2O session _sid_b7e8 closed.
(venv)
CSD@User MINGW64 ~/prescriptive-dga-detector
$ [200~python 2_analyze_domain.py --domain google.com
bash: [200~python: command not found
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain t7xg9q12znd8vh.net
[+] Input domain: t7xg9q12znd8vh.net
[+] Computed features → Length: 18, Entropy: 3.95
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_dtx2rt
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 29.6%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 't7xg9q12znd8vh.net'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 29.6% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.95 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 18 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generate ID]
**Date/Time:** [Auto-generate Timestamp]
**Alert Source:** DGA Detection Model
**Alert Severity:** Medium (Confidence: 29.6%)

**1. Initial Triage & Validation:**

* **Action:** Verify the domain's existence using a DNS lookup tool (e.g., `nslookup`, `dig`).  Note the IP address(es) returned, if any.
* **Action:** Check if the IP address(es) are associated with known malicious infrastructure using threat intelligence feeds (e.g., VirusTotal, MISP, ThreatCrowd).
* **Action:** Review the domain registration information (registrar, registrant details, creation date) using WHOIS lookup tools.  Look for suspicious patterns (e.g., anonymous registration, privacy protection).
* **Action:** Assess the confidence level (29.6%) in light of other indicators. Low confidence requires careful consideration before escalating.

**2. Investigation & Analysis:**

* **Action:** Analyze network traffic related to the suspected DGA domain. If the domain resolves to an IP address, examine network flows involving that IP using a network monitoring tool (e.g., SIEM, packet capture analysis). Look for unusual outbound connections, high volume of traffic, or connections to known malicious IPs/networks.
* **Action:** Investigate if any internal systems attempted to resolve or connect to this domain.  This involves analyzing logs from DNS servers, web browsers, and other relevant applications. Identify affected systems/users.
* **Action:** If the domain is linked to a specific malware family, review the associated threat intelligence to understand potential impact and further actions required.

**3. Containment & Eradication:**

* **Action:** If the investigation confirms malicious activity, block the domain at the network perimeter (firewall, DNS filtering).
* **Action:** If affected systems are identified, isolate them from the network to prevent further compromise.
* **Action:** Initiate malware analysis of affected systems. Consider using sandbox environments for safe analysis.
* **Action:** If malware is found, implement a remediation strategy, which might involve removing the malware, restoring from backups, or reinstalling operating systems.


**4. Post-Incident Activity:**

* **Action:** Document the entire incident response process, including all actions taken, findings, and remediation steps.
* **Action:** Update threat intelligence feeds with the identified malicious domain and IP address(es).
* **Action:** Review security controls and identify any gaps that allowed the DGA domain to be accessed.  This could include weaknesses in DNS security, lack of robust endpoint protection, or insufficient threat intelligence coverage.
* **Action:** Implement necessary changes to prevent similar incidents in the future. This might involve enhancing firewall rules, deploying better endpoint detection and response (EDR) solutions, or improving security awareness training for users.


**5. Escalation:**

Escalate the incident to a higher level if:

* The confidence level increases significantly.
* The impact on the organization is substantial.
* The investigation reveals a widespread compromise.


**Model Explanation Context:**

The high entropy (3.95) and length (18) values suggest a randomly generated domain name, a common characteristic of DGAs.  However, the relatively low confidence (29.6%) indicates that other features might be mitigating this initial assessment.  Thorough investigation is crucial to determine the actual malicious nature of the domain.  Further investigation should be guided by other correlated alerts or events.
Closing connection _sid_82c6 at exit
H2O session _sid_82c6 closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain unknownhost123.biz
[+] Input domain: unknownhost123.biz
[+] Computed features → Length: 18, Entropy: 3.79
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_r0cz09
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 27.1%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'unknownhost123.biz'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 27.1% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.79 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 18 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generate ID]
**Date/Time:** [Timestamp]
**Alert Source:** DGA Detection Model
**Alert Type:** Potential DGA Domain Detected

**1. Initial Assessment & Triage (Analyst Level 1)**

* **Action 1:** Verify the alert details. Confirm the domain ("unknownhost123.biz") and the associated confidence level (27.1%).  Note that this is a relatively low confidence score; further investigation is critical.
* **Action 2:** Check if the domain is already known (e.g., VirusTotal, ThreatCrowd, passive DNS databases). If it's flagged malicious, proceed to Section 2. If not, continue to Action 3.
* **Action 3:** Review the model's explanation.  Note the high entropy (3.79) and length (18) values.  This suggests a randomly generated domain name, a characteristic of DGAs.  However, the low confidence score warrants caution.
* **Action 4:**  Investigate the source of the alert.  Where was this domain observed?  (e.g., DNS logs, network traffic, endpoint logs). Identify affected systems or users if possible.
* **Action 5:** Assign a severity level based on the context.  Given the low confidence and lack of immediate confirmation, initially assign a low to medium severity. This might be upgraded later.

**2. Investigation & Confirmation (Analyst Level 2)**

* **Action 6:** Perform deeper analysis using additional tools.  Investigate the domain's DNS records (A, AAAA, MX, TXT). Check for unusual or nonexistent records.
* **Action 7:** Analyze network traffic associated with the domain.  Look for unusual communication patterns (e.g., high volume, unusual ports, encrypted traffic).  If the domain is resolving, consider capturing network traffic for deeper malware analysis.
* **Action 8:** Analyze endpoint logs from systems that contacted the domain (if identified in Action 4). Look for suspicious activity related to the domain.
* **Action 9:** Consult threat intelligence feeds for similar domains or patterns.  Search for related malware families or campaigns.
* **Action 10:** If evidence strongly suggests malicious activity (e.g., communication with known C2 servers, malware downloads), escalate to Section 3.  If not, document findings and update the alert severity.

**3. Containment & Remediation (Analyst Level 3)**

* **Action 11:**  If the domain is confirmed as malicious, block access to it at the network perimeter (firewall, proxy) and on affected endpoints (host-based firewall).
* **Action 12:** Initiate malware analysis of any downloaded files associated with the domain.
* **Action 13:** Investigate the infection vector. How did the compromised system(s) come into contact with the DGA?
* **Action 14:** Perform affected system remediation. This includes removing malware, updating antivirus software, patching vulnerabilities, and restoring from backups if necessary.    
* **Action 15:** Monitor for further activity from the domain or related domains.


**4. Post-Incident Activity**

* **Action 16:** Document all findings and actions taken in a comprehensive incident report.
* **Action 17:** Update the DGA detection model with the new data (if applicable).
* **Action 18:** Implement preventative measures to reduce the likelihood of future DGA-related incidents.  This might include improving DNS security, enhancing endpoint detection and response capabilities, and improving employee security awareness training.
* **Action 19:** Conduct a post-incident review to identify areas for improvement in the incident response process.


**Escalation:**  Escalate to senior security personnel or management if the incident is severe, involves critical systems, or requires significant resources.


**Note:** The low confidence score (27.1%) highlights the importance of thorough investigation.  Do not solely rely on the DGA model's output;  use it as one piece of evidence in a broader investigation.  Always correlate findings from multiple sources before taking action.
Closing connection _sid_a89c at exit
H2O session _sid_a89c closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain google.com
[+] Input domain: google.com
[+] Computed features → Length: 10, Entropy: 2.65
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_uuvtja
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: LEGIT (Confidence: 99.6%)
[+] Domain appears legitimate. No playbook generated.
Closing connection _sid_b469 at exit
H2O session _sid_b469 closed.
(venv)CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain kq3v9z7j1x5f8g2h.info
[+] Input domain: kq3v9z7j1x5f8g2h.info
[+] Computed features → Length: 21, Entropy: 4.3
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpv0b6v8r6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_1d4j56
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 36.0%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'kq3v9z7j1x5f8g2h.info'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 36.0% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 4.3 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 21 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:**  [Auto-generated ID]
**Date/Time:** [Auto-generated Timestamp]
**Alert Source:** DGA Detection Model
**Severity:** Medium (Adjustable based on context and further investigation)

**1. Initial Triage & Validation:**

* **Action:** Verify the alert.  Cross-reference the domain ('kq3v9z7j1x5f8g2h.info') against known threat intelligence feeds (e.g., VirusTotal, ThreatCrowd). Check for existing entries in your SIEM/SOAR system related to this domain.
* **Expected Outcome:** Confirmation of the domain's existence and identification of any malicious activity associated with it.  VirusTotal/ThreatCrowd reports should be included in the incident report.
* **Responsible Party:** SOC Analyst Level 1
* **Time Estimate:** 15-30 minutes

**2. Domain Investigation:**

* **Action:** Perform a WHOIS lookup to identify the registrant information and registration date. Investigate the domain's DNS records (A, AAAA, MX, etc.) to identify any associated IP addresses and potential hosting providers. Check for any SSL certificates associated with the domain.
* **Expected Outcome:**  Identification of the domain's registrant, hosting provider, and associated IP addresses.  Determination of the domain's purpose (if any).
* **Responsible Party:** SOC Analyst Level 1
* **Time Estimate:** 30-60 minutes

**3. Network Traffic Analysis:**

* **Action:** If the domain resolves to an IP address, analyze network traffic logs (firewall, IDS/IPS, proxy logs) for any communication involving this IP address or domain.  Pay close attention to connections originating from internal systems.
* **Expected Outcome:** Identification of any compromised systems communicating with the malicious domain.  Determination of the volume and type of traffic.
* **Responsible Party:** SOC Analyst Level 2
* **Time Estimate:** 60-120 minutes

**4. System Isolation & Remediation:**

* **Action:** If compromised systems are identified, isolate them from the network to prevent further compromise.  Initiate malware analysis and remediation steps on affected systems. This may involve deploying endpoint detection and response (EDR) tools.
* **Expected Outcome:**  Compromised systems isolated and secured. Malware removed and vulnerabilities patched.
* **Responsible Party:** SOC Analyst Level 2/Incident Response Team
* **Time Estimate:** Variable, depending on the extent of compromise

**5. Threat Hunting & Containment:**

* **Action:** Expand the investigation to identify any other domains generated by the same DGA algorithm.  Utilize threat intelligence platforms and sandboxing technologies to analyze any associated malware.  Consider using YARA rules to detect similar domains.
* **Expected Outcome:**  Identification and mitigation of any additional threats associated with the DGA.
* **Responsible Party:** SOC Analyst Level 3/Threat Hunter
* **Time Estimate:** Variable

**6. Post-Incident Activities:**

* **Action:** Document all findings in a detailed incident report.  Update security controls and processes to prevent similar incidents in the future.  Consider implementing DGA detection and prevention tools at a broader level.  Communicate findings to relevant stakeholders.      
* **Expected Outcome:**  Complete incident report, improved security posture, and informed stakeholders.
* **Responsible Party:** SOC Analyst Level 1/Incident Response Team
* **Time Estimate:** Variable


**AI Model Confidence Note:** The AI model flagged this domain with 36% confidence, which is relatively low.  While the high entropy and length values are suspicious, manual validation and further investigation are crucial to confirm malicious intent.  The playbook emphasizes thorough investigation before undertaking drastic actions.

**Escalation Criteria:**  Escalate to higher-level SOC analysts or the Incident Response Team if:
* Multiple systems are affected.
* Critical systems are compromised.
* Significant data exfiltration is suspected.
* The investigation exceeds allocated resources.
Closing connection _sid_8518 at exit
H2O session _sid_8518 closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain amazon.com
[+] Input domain: amazon.com
[+] Computed features → Length: 10, Entropy: 2.72
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmp57cko9u6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_086xyk
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: LEGIT (Confidence: 99.5%)
[+] Domain appears legitimate. No playbook generated.
Closing connection _sid_9459 at exit
H2O session _sid_9459 closed.
(venv)
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain lksdjf9347xxp.biz
^C
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain lksdjf9347xxp.biz
[+] Input domain: lksdjf9347xxp.biz
[+] Computed features → Length: 17, Entropy: 3.97
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpvx5pc4e6\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_j96uyu
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 27.9%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'lksdjf9347xxp.biz'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 27.9% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.97 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 17 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generated ID]
**Date/Time:** [Timestamp]
**Alert Source:** DGA Detection Model
**Severity:** Medium (initially, can escalate)

**1. Initial Assessment & Triage:**

* **Verify Alert:** Confirm the alert details (domain: 'lksdjf9347xxp.biz') and associated metadata from the DGA detection system. Review the raw logs leading to the alert.
* **Model Confidence:** Note the model's confidence level (27.9%). While not overwhelmingly high, the contributing factors warrant investigation.
* **Threat Intelligence Check:** Query threat intelligence platforms (e.g., VirusTotal, MISP, ThreatConnect) for the domain 'lksdjf9347xxp.biz'.  Look for existing malicious classifications, reports, or associations.
* **Internal System Check:**  Determine if any internal systems have contacted or attempted to contact this domain. Review DNS logs, firewall logs, and network traffic logs (if available).

**2. Investigation & Containment:**

* **Domain Resolution:** Perform a DNS lookup for the domain to resolve its IP address(es).  Note the IP address(es) and their geolocation.
* **IP Address Investigation:** Investigate the resolved IP address(es) using threat intelligence platforms.  Check for known malicious activity associated with these IPs.
* **Network Segmentation (if applicable):** If the domain is found to be malicious and internal systems have contacted it, consider isolating affected systems from the network to prevent further compromise.
* **Traffic Analysis:** Analyze network traffic associated with the domain and resolved IP addresses to identify potential compromised systems or data exfiltration attempts.  Pay close attention to unusual outbound connections.
* **Malware Analysis (if applicable):** If malware is suspected, collect samples (if possible and safe) for analysis in a sandboxed environment.

**3. Remediation & Recovery:**

* **Block the Domain:** Implement a block rule in the firewall and DNS to prevent access to 'lksdjf9347xxp.biz' and any associated IP addresses.
* **Remediate Compromised Systems:** If internal systems are compromised, follow established incident response procedures for malware removal and system hardening (including patching and password resets).
* **Log Analysis:** Thoroughly review logs to identify the scope of the compromise and potential impact.
* **User Notification:** Inform affected users (if any) of the incident and any necessary actions.

**4. Post-Incident Activities:**

* **Reporting:** Generate a detailed incident report summarizing the findings, actions taken, and lessons learned.
* **Model Feedback:** Provide feedback to the DGA detection model team regarding the alert, focusing on the model’s confidence level and the accuracy of the alert. This will help improve the model's performance over time.
* **Security Awareness Training:** If the incident involves user interaction (e.g., phishing), consider providing additional security awareness training to users.
* **Update Procedures:** Review existing security controls and procedures to determine if any improvements are necessary to prevent similar incidents in the future.


**Escalation Criteria:**

* High confidence level from the DGA detection model.
* Identification of malicious activity associated with the domain/IP address.
* Evidence of data exfiltration or system compromise.
* Impact to critical business functions.


**Note:** This playbook provides a general framework. Specific actions may need to be adjusted depending on the organization's security infrastructure, policies, and the severity of the incident.  Always prioritize data protection and minimizing business disruption.
Closing connection _sid_b7e8 at exit
H2O session _sid_b7e8 closed.
(venv)
CSD@User MINGW64 ~/prescriptive-dga-detector
$ [200~python 2_analyze_domain.py --domain google.com
bash: [200~python: command not found
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain t7xg9q12znd8vh.net
[+] Input domain: t7xg9q12znd8vh.net
[+] Computed features → Length: 18, Entropy: 3.95
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmp4kg19izf\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_dtx2rt
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 29.6%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 't7xg9q12znd8vh.net'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 29.6% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.95 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 18 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generate ID]
**Date/Time:** [Auto-generate Timestamp]
**Alert Source:** DGA Detection Model
**Alert Severity:** Medium (Confidence: 29.6%)

**1. Initial Triage & Validation:**

* **Action:** Verify the domain's existence using a DNS lookup tool (e.g., `nslookup`, `dig`).  Note the IP address(es) returned, if any.
* **Action:** Check if the IP address(es) are associated with known malicious infrastructure using threat intelligence feeds (e.g., VirusTotal, MISP, ThreatCrowd).
* **Action:** Review the domain registration information (registrar, registrant details, creation date) using WHOIS lookup tools.  Look for suspicious patterns (e.g., anonymous registration, privacy protection).
* **Action:** Assess the confidence level (29.6%) in light of other indicators. Low confidence requires careful consideration before escalating.

**2. Investigation & Analysis:**

* **Action:** Analyze network traffic related to the suspected DGA domain. If the domain resolves to an IP address, examine network flows involving that IP using a network monitoring tool (e.g., SIEM, packet capture analysis). Look for unusual outbound connections, high volume of traffic, or connections to known malicious IPs/networks.
* **Action:** Investigate if any internal systems attempted to resolve or connect to this domain.  This involves analyzing logs from DNS servers, web browsers, and other relevant applications. Identify affected systems/users.
* **Action:** If the domain is linked to a specific malware family, review the associated threat intelligence to understand potential impact and further actions required.

**3. Containment & Eradication:**

* **Action:** If the investigation confirms malicious activity, block the domain at the network perimeter (firewall, DNS filtering).
* **Action:** If affected systems are identified, isolate them from the network to prevent further compromise.
* **Action:** Initiate malware analysis of affected systems. Consider using sandbox environments for safe analysis.
* **Action:** If malware is found, implement a remediation strategy, which might involve removing the malware, restoring from backups, or reinstalling operating systems.


**4. Post-Incident Activity:**

* **Action:** Document the entire incident response process, including all actions taken, findings, and remediation steps.
* **Action:** Update threat intelligence feeds with the identified malicious domain and IP address(es).
* **Action:** Review security controls and identify any gaps that allowed the DGA domain to be accessed.  This could include weaknesses in DNS security, lack of robust endpoint protection, or insufficient threat intelligence coverage.
* **Action:** Implement necessary changes to prevent similar incidents in the future. This might involve enhancing firewall rules, deploying better endpoint detection and response (EDR) solutions, or improving security awareness training for users.


**5. Escalation:**

Escalate the incident to a higher level if:

* The confidence level increases significantly.
* The impact on the organization is substantial.
* The investigation reveals a widespread compromise.


**Model Explanation Context:**

The high entropy (3.95) and length (18) values suggest a randomly generated domain name, a common characteristic of DGAs.  However, the relatively low confidence (29.6%) indicates that other features might be mitigating this initial assessment.  Thorough investigation is crucial to determine the actual malicious nature of the domain.  Further investigation should be guided by other correlated alerts or events.
Closing connection _sid_82c6 at exit
H2O session _sid_82c6 closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain unknownhost123.biz
[+] Input domain: unknownhost123.biz
[+] Computed features → Length: 18, Entropy: 3.79
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpsk090vei\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_r0cz09
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: DGA (Confidence: 27.1%)

=== XAI Summary ===

- Alert: Potential DGA domain detected.
- Domain: 'unknownhost123.biz'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with 27.1% confidence. The classification was primarily driven by:
  - A high 'entropy' value of 3.79 (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of 18 (which also pushed the prediction towards 'dga').


=== Generating Incident Response Playbook ===

## Incident Response Playbook: Potential DGA Domain Detected

**Incident ID:** [Auto-generate ID]
**Date/Time:** [Timestamp]
**Alert Source:** DGA Detection Model
**Alert Type:** Potential DGA Domain Detected

**1. Initial Assessment & Triage (Analyst Level 1)**

* **Action 1:** Verify the alert details. Confirm the domain ("unknownhost123.biz") and the associated confidence level (27.1%).  Note that this is a relatively low confidence score; further investigation is critical.
* **Action 2:** Check if the domain is already known (e.g., VirusTotal, ThreatCrowd, passive DNS databases). If it's flagged malicious, proceed to Section 2. If not, continue to Action 3.
* **Action 3:** Review the model's explanation.  Note the high entropy (3.79) and length (18) values.  This suggests a randomly generated domain name, a characteristic of DGAs.  However, the low confidence score warrants caution.
* **Action 4:**  Investigate the source of the alert.  Where was this domain observed?  (e.g., DNS logs, network traffic, endpoint logs). Identify affected systems or users if possible.
* **Action 5:** Assign a severity level based on the context.  Given the low confidence and lack of immediate confirmation, initially assign a low to medium severity. This might be upgraded later.

**2. Investigation & Confirmation (Analyst Level 2)**

* **Action 6:** Perform deeper analysis using additional tools.  Investigate the domain's DNS records (A, AAAA, MX, TXT). Check for unusual or nonexistent records.
* **Action 7:** Analyze network traffic associated with the domain.  Look for unusual communication patterns (e.g., high volume, unusual ports, encrypted traffic).  If the domain is resolving, consider capturing network traffic for deeper malware analysis.
* **Action 8:** Analyze endpoint logs from systems that contacted the domain (if identified in Action 4). Look for suspicious activity related to the domain.
* **Action 9:** Consult threat intelligence feeds for similar domains or patterns.  Search for related malware families or campaigns.
* **Action 10:** If evidence strongly suggests malicious activity (e.g., communication with known C2 servers, malware downloads), escalate to Section 3.  If not, document findings and update the alert severity.

**3. Containment & Remediation (Analyst Level 3)**

* **Action 11:**  If the domain is confirmed as malicious, block access to it at the network perimeter (firewall, proxy) and on affected endpoints (host-based firewall).
* **Action 12:** Initiate malware analysis of any downloaded files associated with the domain.
* **Action 13:** Investigate the infection vector. How did the compromised system(s) come into contact with the DGA?
* **Action 14:** Perform affected system remediation. This includes removing malware, updating antivirus software, patching vulnerabilities, and restoring from backups if necessary.    
* **Action 15:** Monitor for further activity from the domain or related domains.


**4. Post-Incident Activity**

* **Action 16:** Document all findings and actions taken in a comprehensive incident report.
* **Action 17:** Update the DGA detection model with the new data (if applicable).
* **Action 18:** Implement preventative measures to reduce the likelihood of future DGA-related incidents.  This might include improving DNS security, enhancing endpoint detection and response capabilities, and improving employee security awareness training.
* **Action 19:** Conduct a post-incident review to identify areas for improvement in the incident response process.


**Escalation:**  Escalate to senior security personnel or management if the incident is severe, involves critical systems, or requires significant resources.


**Note:** The low confidence score (27.1%) highlights the importance of thorough investigation.  Do not solely rely on the DGA model's output;  use it as one piece of evidence in a broader investigation.  Always correlate findings from multiple sources before taking action.
Closing connection _sid_a89c at exit
H2O session _sid_a89c closed.
(venv) 
CSD@User MINGW64 ~/prescriptive-dga-detector
$ python 2_analyze_domain.py --domain google.com
[+] Input domain: google.com
[+] Computed features → Length: 10, Entropy: 2.65
Checking whether there is an H2O instance running at http://localhost:54321..... not found.
Attempting to start a local H2O server...
; OpenJDK 64-Bit Server VM Microsoft-11367275 (build 11.0.27+6-LTS, mixed mode, sharing)
  Starting server from C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\backend\bin\h2o.jar
  Ice root: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl
  JVM stdout: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl\h2o_CSD_started_from_python.out
  JVM stderr: C:\Users\CSD\AppData\Local\Temp\tmpsjzw_5gl\h2o_CSD_started_from_python.err
  Server is running at http://127.0.0.1:54321
Connecting to H2O server at http://127.0.0.1:54321 ... successful.
Warning: Your H2O cluster version is (4 months and 23 days) old.  There may be a newer version available.
Please download and install the latest version from: https://h2o-release.s3.amazonaws.com/h2o/latest_stable.html
--------------------------  -----------------------------
H2O_cluster_uptime:         03 secs
H2O_cluster_timezone:       Africa/Lagos
H2O_data_parsing_timezone:  UTC
H2O_cluster_version:        3.46.0.7
H2O_cluster_version_age:    4 months and 23 days
H2O_cluster_name:           H2O_from_python_CSD_uuvtja
H2O_cluster_total_nodes:    1
H2O_cluster_free_memory:    7.920 Gb
H2O_cluster_total_cores:    20
H2O_cluster_allowed_cores:  20
H2O_cluster_status:         locked, healthy
H2O_connection_url:         http://127.0.0.1:54321
H2O_connection_proxy:       {"http": null, "https": null}
H2O_internal_security:      False
Python_version:             3.12.9 final
--------------------------  -----------------------------
generic Model Build progress: |██████████████████████████████████████████████████ (done)| 100%
Parse progress: |████████████████████████████████████████████████████████████████ (done)| 100%
generic prediction progress: |███████████████████████████████████████████████████ (done)| 100%
C:\Users\CSD\prescriptive-dga-detector\venv\Lib\site-packages\h2o\frame.py:1983: H2ODependencyWarning: Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using multi-thread, install polars and pyarrow and use it as pandas_df = h2o_df.as_data_frame(use_multi_thread=True)

  warnings.warn("Converting H2O frame to pandas dataframe using single-thread.  For faster conversion using"
[+] Prediction: LEGIT (Confidence: 99.6%)
[+] Domain appears legitimate. No playbook generated.
Closing connection _sid_b469 at exit
H2O session _sid_b469 closed.
(venv)



```
[+] Prediction: DGA (Confidence: 36.0%)

=== XAI Summary ===
- Domain: 'kq3v9z7j1x5f8g2h.info'
- AI Model Explanation:
  - Entropy: 4.3 (high)
  - Length: 21 (long)

=== Incident Response Playbook ===
1. Triage with VirusTotal
2. WHOIS + DNS record lookup
3. Check internal traffic
4. Isolate compromised systems
5. Hunt similar domains
6. Document and patch
```

License

MIT License


Author

Created by OLALEYE OLATOKUNBO



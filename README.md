# Prescriptive DGA Detector: From Black Box to Playbook

This project demonstrates an end-to-end security analytics workflow integrating:

* **H2O AutoML** for domain classification (legit vs. DGA)
* **Explainable AI (XAI)** to justify predictions using entropy and length features
* **Google Generative AI (Gemini)** to auto-generate tailored incident response playbooks

## Overview

Cybersecurity teams face growing threats from malware using Domain Generation Algorithms (DGAs) to evade detection. This tool helps defenders rapidly:

1. **Classify** suspicious domains as legit or DGA
2. **Explain** model reasoning using interpretable features
3. **Prescribe** concrete SOC actions using GenAI-generated playbooks

---

## How It Works (Pipeline Architecture)

```
User Input (domain)
   └──> [Feature Engineering: length, entropy]
         └──> [H2O AutoML Model Prediction (MOJO)]
               └──> [SHAP-style Explanation (XAI)]
                     └──> [GenAI Prompting]
                           └──> ��� Incident Response Playbook
```

---

##  Installation

```bash
git clone https://github.com/yourusername/prescriptive-dga-detector
cd prescriptive-dga-detector
python -m venv venv
source venv/bin/activate  # Or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

Ensure your **Google Generative AI API key** is exported:

```bash
export GOOGLE_API_KEY="my-api-key"
```

---

## my Model Training

```bash
python 1_train_and_export.py
```

* Trains an H2O AutoML model using entropy/length features
* Saves the best MOJO model to `model/DGA_Leader.zip`

---

##  Domain Analysis (Main Script)

```bash
python 2_analyze_domain.py --domain kq3v9z7j1x5f8g2h.info
```

**Output Includes:**

* Domain prediction (legit or DGA)
* XAI explanation summary
* Gemini-generated incident response playbook

---

## Project Structure

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



##  Example Output 

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



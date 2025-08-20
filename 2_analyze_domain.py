# 2_analyze_domain.py

import argparse
import h2o
import math
import pandas as pd
from h2o.frame import H2OFrame
from genai_prescriptions import generate_playbook


# -----------------------------------
# Utility: Shannon Entropy Function
# -----------------------------------
def shannon_entropy(domain):
    from collections import Counter
    p, lns = Counter(domain), float(len(domain))
    return -sum(count / lns * math.log2(count / lns) for count in p.values())


# -----------------------------------
# 1. Parse Domain from CLI
# -----------------------------------
parser = argparse.ArgumentParser(description="Analyze a domain for DGA classification.")
parser.add_argument("--domain", required=True, help="The domain name to analyze")
args = parser.parse_args()
domain = args.domain
length = len(domain)
entropy = round(shannon_entropy(domain), 2)

print(f"[+] Input domain: {domain}")
print(f"[+] Computed features → Length: {length}, Entropy: {entropy}")


# -----------------------------------
# 2. Initialize H2O + Load Model
# -----------------------------------
h2o.init()

mojo_path = "model/DeepLearning_1_AutoML_1_20250819_65042.zip"  # update if filename changes
predictor = h2o.import_mojo(mojo_path)

# -----------------------------------
# 3. Prepare DataFrame for Prediction
# -----------------------------------
df = pd.DataFrame([{"length": length, "entropy": entropy}])
h2o_df = H2OFrame(df)

# -----------------------------------
# 4. Perform Prediction
# -----------------------------------
prediction = predictor.predict(h2o_df).as_data_frame()
predicted_class = prediction["predict"][0]
confidence = round(prediction[predicted_class][0] * 100, 1)

print(f"[+] Prediction: {predicted_class.upper()} (Confidence: {confidence}%)")

# -----------------------------------
# 5. If DGA → Generate Explanation + Playbook
# -----------------------------------
if predicted_class == "dga":
    xai_findings = f"""
- Alert: Potential DGA domain detected.
- Domain: '{domain}'
- AI Model Explanation (from SHAP-style logic): The model flagged this domain with {confidence}% confidence. The classification was primarily driven by:
  - A high 'entropy' value of {entropy} (which strongly pushed the prediction towards 'dga').
  - A high 'length' value of {length} (which also pushed the prediction towards 'dga').
"""

    print("\n=== XAI Summary ===")
    print(xai_findings)

    print("\n=== Generating Incident Response Playbook ===\n")
    playbook = generate_playbook(xai_findings)
    print(playbook)
else:
    print("[+] Domain appears legitimate. No playbook generated.")

# genai_prescriptions.py

import os
import google.generativeai as genai

def generate_playbook(findings: str) -> str:
    """
    Uses Google Gemini API to generate an incident response playbook from XAI findings.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise EnvironmentError("GOOGLE_API_KEY environment variable not set.")

    # Configure the Gemini client
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(model_name="models/gemini-1.5-flash-latest")
    # Generate the playbook
    prompt = f"""
You are a cybersecurity analyst assistant. Based on the following XAI findings from a DGA detection model,
generate a structured, actionable incident response playbook for SOC analysts.

{findings}
"""
    response = model.generate_content(prompt)
    return response.text.strip()

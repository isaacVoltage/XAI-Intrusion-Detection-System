Intrusion Detection through xAI
Overview

Intrusion Detection through xAI is a Security-as-a-Service (SECaaS) platform that provides real-time intrusion detection with explainable machine learning. The system monitors live network traffic, detects malicious behavior, explains predictions using SHAP, and automatically blocks attacker IPs.
The objective is to reduce the reaction time of security analysts while improving trust in AI-driven decisions.

Features
Real-time network packet monitoring using Scapy
Machine Learning-based attack detection using Random Forest
Explainable AI using SHAP for feature-level analysis
Automatic firewall rule generation using PowerShell
SOC Dashboard for live monitoring and threat visualization
Detection and prevention completed within low-latency execution windows

System Workflow
Capture live network packets
Convert packets into 41 statistical features
Run prediction using Random Forest
Generate SHAP explanations
Identify malicious traffic
Automatically block attacker IP
Display logs and alerts on SOC Dashboard

Implementation
<img width="3" height="7" alt="image" src="https://github.com/user-attachments/assets/2d04bb1a-63e1-4981-938b-7cb45eac6a34" />
SOC Dashboard interface
<img width="897" height="206" alt="image" src="https://github.com/user-attachments/assets/3c8259c3-9b16-48dd-94c1-d85a17e52e30" />
Command line in Kali Linux for Dos attack
<img width="910" height="475" alt="image" src="https://github.com/user-attachments/assets/e8845d00-2825-4bbb-ac79-86ae4ba06c87" />
SOC dashboard during DOS attack
<img width="910" height="75" alt="image" src="https://github.com/user-attachments/assets/266c27dc-3801-4605-8f65-7362e4bc914b" />
Firewall creation for DOS attack
<img width="918" height="125" alt="image" src="https://github.com/user-attachments/assets/75abd731-6b10-4162-998d-ce7b276e88d9" />
Command line in kali linux for port scan
<img width="1160" height="689" alt="image" src="https://github.com/user-attachments/assets/1e4579da-d7d0-40da-9481-15a4bd45bc9d" />
SHap value graph for Nmap attack

Installation
git clone <repository-link>
cd intrusion-detection-xai

pip install scapy
pip install scikit-learn
pip install shap
pip install joblib

Run:
python main.py

Authors
Isaac Gomes
Harris Gonsalves
Aditya Bagad
Nishant Singh



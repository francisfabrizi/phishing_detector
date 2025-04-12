# 🛡️ Phishing Email Detector (Python + GUI)

This project is a phishing email detector I built to demonstrate my understanding of how phishing detection works and why it’s critical in cybersecurity. It scans `.eml` email files, analyses them for common phishing red flags and scores each message based on its threat level.

The tool uses a Python backend with a simple GUI interface to make the analysis interactive and user-friendly. Results can be exported to CSV for further investigation or reporting.

## 🔍 What It Does

- Parses `.eml` files and extracts:
  - The email subject
  - Sender information
  - Email body content
  - Embedded links

- Analyses emails for:
  - **Suspicious subjects** (e.g., "Your account is locked")
  - **Unusual senders** (e.g., unknown or suspicious domains)
  - **Phishing phrases** (e.g., "verify your identity", "click here")
  - **Suspicious links** (e.g., containing words like `login`, `secure`, or `update`)

- Scores each email and flags key concerns (e.g., "Suspicious Sender", "Malicious Link")

- Displays results in a GUI table

- Allows exporting of scan results as a CSV file

## 🎯 Why I Built It

Phishing remains one of the most common and dangerous attack vectors. By building this detector from scratch, I wanted to:

- Understand how phishing indicators can be identified through code
- Gain experience parsing email formats and analyzing real-world email components
- Explore how phishing detection can be made accessible to users with simple GUI tools
- Lay the groundwork for future integration with services like VirusTotal or URLScan.io

## 🖥️ Technology Used

- **Python** (core logic)
- **Tkinter** (GUI interface)
- **BeautifulSoup** (for HTML parsing in emails)
- **email** module (to parse `.eml` files)


## 📸 Screenshot

<img width="596" alt="image" src="https://github.com/user-attachments/assets/ea429760-205e-4862-8ffd-07d0a68a5485" />


## 📝 Summary

This phishing detector project reflects my ability to apply cybersecurity concepts in code, build tools with real-world applications, and create interfaces that help users stay safe from online threats. It’s part of my ongoing exploration of practical defensive and offensive security techniques.

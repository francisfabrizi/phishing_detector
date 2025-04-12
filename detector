import os
import csv
import re
from tkinter import filedialog, messagebox, ttk
from tkinter import *
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from datetime import datetime

# ------------------------ FUNCTIONS ------------------------

def parse_email(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

def extract_links(email_content):
    soup = BeautifulSoup(email_content, 'html.parser')
    return [a['href'] for a in soup.find_all('a', href=True)]

def is_suspicious_link(link):
    keywords = ["login", "update", "secure", "account", "verify"]
    return any(k in link.lower() for k in keywords)

# Mock version: Replace this function with actual VirusTotal checks
def scan_link_virustotal(link):
    # In the mock version, we assume no malicious links are found
    return False

def is_unusual_sender(sender_email):
    domain = sender_email.split('@')[-1] if sender_email else ""
    unusual_domains = ["unknown.com", "phishing.com"]
    return domain in unusual_domains

def analyse_content(content):
    suspicious_phrases = [
        "verify your account", "login now", "update your information", "click here",
        "act now", "immediate action required", "your account has been suspended",
        "confirm your identity", "unusual activity detected", "enter your password",
        "provide your ssn", "submit your credit card details", "secure your account",
        "exclusive reward", "your portfolio", "financial growth", "get rich quick",
        "unclaimed rewards", "bonus", "limited time", "special promotion",
        "dear customer", "dear user", "offer ends soon"
    ]
    return any(phrase in content.lower() for phrase in suspicious_phrases)

def analyse_subject(subject):
    suspicious_subjects = [
        "urgent action required", "your account has been locked", "verify your identity",
        "confirm your email", "reset your password", "congratulations, you won",
        "payment required", "security update", "fraudulent activity detected",
        "grow your portfolio", "rewards", "win", "claim", "limited offer", "exclusive deal",
        "next level", "£", "$", "save now", "update", "investment opportunity"
    ]
    return any(s in subject.lower() for s in suspicious_subjects)

def score_email(subject, sender, content, links):
    score = 0
    flags = []

    if analyse_subject(subject):
        score += 1
        flags.append("Suspicious Subject")

    if is_unusual_sender(sender):
        score += 1
        flags.append("Suspicious Sender")

    if analyse_content(content):
        score += 1
        flags.append("Suspicious Content")

    if any(is_suspicious_link(link) for link in links):
        score += 1
        flags.append("Suspicious Link Found")

    if any(scan_link_virustotal(link) for link in links):
        score += 1
        flags.append("VirusTotal Malicious Link")

    return score, flags

def analyse_eml(file_path):
    msg = parse_email(file_path)
    content = msg.get_body(preferencelist=('plain', 'html'))
    email_content = content.get_content() if content else ""
    subject = msg['Subject'] or "(No Subject)"
    sender = msg['From'] or "(Unknown Sender)"
    links = extract_links(email_content)

    score, flags = score_email(subject, sender, email_content, links)

    return {
        'Filename': os.path.basename(file_path),
        'Subject': subject,
        'Sender': sender,
        'Score': score,
        'Flags': ", ".join(flags),
        'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

def export_results_to_csv(results, path):
    keys = results[0].keys()
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)

# ------------------------ GUI ------------------------

class PhishingDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Detector")
        self.results = []

        Label(root, text="Select Folder with .eml Files:").pack(pady=5)
        Button(root, text="Browse", command=self.browse_folder).pack()
        self.folder_label = Label(root, text="No folder selected")
        self.folder_label.pack(pady=5)

        Button(root, text="Scan Emails", command=self.scan_emails).pack(pady=5)

        self.tree = ttk.Treeview(root, columns=("Subject", "Score", "Flags"), show="headings")
        self.tree.heading("Subject", text="Subject")
        self.tree.heading("Score", text="Score")
        self.tree.heading("Flags", text="Flags")
        self.tree.pack(fill=BOTH, expand=True, padx=10, pady=10)

        Button(root, text="Export to CSV", command=self.export_csv).pack(pady=5)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_path = folder
            self.folder_label.config(text=folder)

    def scan_emails(self):
        if not hasattr(self, 'folder_path'):
            messagebox.showerror("Error", "No folder selected")
            return

        self.tree.delete(*self.tree.get_children())
        self.results = []

        for filename in os.listdir(self.folder_path):
            if filename.endswith(".eml"):
                file_path = os.path.join(self.folder_path, filename)
                result = analyse_eml(file_path)
                self.results.append(result)
                self.tree.insert("", END, values=(result['Subject'], result['Score'], result['Flags']))

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("Info", "No results to export")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if path:
            export_results_to_csv(self.results, path)
            messagebox.showinfo("Success", f"Results exported to {path}")

# ------------------------ MAIN ------------------------

if __name__ == '__main__':
    root = Tk()
    root.geometry("800x600")
    app = PhishingDetectorGUI(root)
    root.mainloop()

#étape 6 : génération d'alertes et d'email
"""Nous avons mis en place un système d’alerte pour identifier automatiquement les vulnérabilités critiques, en nous basant sur les critères suivants :

    - Score CVSS ≥ 8 (Base_Severity = Critical)
       OU
    - EPSS ≥ 0.8

Lorsqu’une vulnérabilité remplit ces conditions, un email d’alerte peut être généré pour informer rapidement l’équipe de sécurité."""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import smtplib
from email.mime.text import MIMEText

# Chargement du DataFrame
csv_path = "DataFrame.csv"
df = pd.read_csv(csv_path, encoding="utf-8")


#fonction qui permet d'envoyer l'email
def send_email(to_email, subject, body):
    from_email = "anaelle.pollart@gmail.com" #"votre_email@gmail.com"
    password = "oahg ulrk oqsc tiyd" #"mot_de_passe_application"

    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

# Préparation des alertes
print("\n Simulation des alertes critiques par email")
df["EPSS_score"] = pd.to_numeric(df["EPSS_score"], errors="coerce")
df["CVSS_score"] = pd.to_numeric(df["CVSS_score"], errors="coerce")

alertes = df[(df["CVSS_score"] >= 8) | (df["EPSS_score"] >= 0.8)]

for _, row in alertes.iterrows():
    produit = row["Produit"]
    cve = row["CVE_ID"]
    lien = row["Lien_bulletin"]
    description = row["Description"]
    message = f"Une vulnérabilité critique a été détectetée sur {produit}.\nCVE : {cve}\nLien : {lien}\n\n{description}"
    #affichage des alertes dans la console
    print(f"[SIMULATION] Alerte envoyée pour {cve}")
    
    #envoi alertes par email
    send_email("anaelle.pollart@gmail.com", f"Alerte critique : {cve}", message)

    #send_email("votre_email@gmail.com", f"Alerte critique : {cve}", message)
    




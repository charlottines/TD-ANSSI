import pandas as pd
import smtplib
from email.mime.text import MIMEText
import os

def envoyer_alertes(from_email, password, to_email, subject="Alerte critique"):
    # Chargement du DataFrame
    csv_path = os.path.join(os.path.dirname(__file__), "DataFrame.csv")
    df = pd.read_csv(csv_path, encoding="utf-8")

    print("\n📊 Simulation des alertes critiques par email")
    df["EPSS_score"] = pd.to_numeric(df["EPSS_score"], errors="coerce")
    df["CVSS_score"] = pd.to_numeric(df["CVSS_score"], errors="coerce")

    alertes = df[(df["CVSS_score"] >= 8) & (df["EPSS_score"] >= 0.7)]
    if alertes.empty:
        print(" Aucune vulnérabilité critique détectée.")
        return False, [" Aucune vulnérabilité critique détectée."]

    messages = []

    for _, row in alertes.iterrows():
        produit = str(row.get("Produit", "N/A"))
        cve = str(row.get("CVE_ID", "N/A"))
        lien = str(row.get("Lien_bulletin", "N/A"))
        description = str(row.get("Description", "N/A"))
        cvss = str(row.get("CVSS_score", "N/A"))
        epss = str(row.get("EPSS_score", "N/A"))

        body = f"""🚨 Vulnérabilité critique détectée :

Produit       : {produit}
CVE ID        : {cve}
Score CVSS    : {cvss}
Score EPSS    : {epss}
Lien Bulletin : {lien}
Description   : {description.strip()[:300]}{'...' if len(description) > 300 else ''}
"""

        print("\n" + "="*70)
        print(f"ALERTE : {cve}")
        print("-" * 70)
        print(body)
        print("="*70 + "\n")

        # Envoi de l'e-mail
        msg = MIMEText(body)
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = f"{subject} : {cve}"

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()

        messages.append(body)

    return True, messages

# ✅ Mode script autonome
if __name__ == "__main__":
    print("=== Envoi manuel des alertes depuis alertes_mail.py ===")
    from_email = input("Email expéditeur : ")
    password = input("Mot de passe d'application Gmail : ")
    to_email = input("Email destinataire : ")
    subject = input("Sujet (laisser vide pour 'Alerte critique') : ") or "Alerte critique"

    success, messages = envoyer_alertes(from_email, password, to_email, subject)
    if success:
        print(f"\n✅ {len(messages)} alerte(s) envoyée(s) avec succès.")
    else:
        print("\nℹ️ Aucune alerte envoyée.")
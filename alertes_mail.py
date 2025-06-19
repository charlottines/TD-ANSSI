# étape 6 : génération d'alertes et d'email

# Nous avons mis en place un système d’alerte pour identifier automatiquement les vulnérabilités critiques, en nous basant sur les critères suivants : 
# Score CVSS ≥ 8 ET EPSS ≥ 0.7
# Cela permet de cibler uniquement les failles à la fois critiques et avec une forte probabilité d’attaque effective, donc vraiment prioritaires 

# Une fois le programme lancé, l'utilisateur à le choix d'afficher les alertes critiques dans la consoles ou de les envoyés par mail 

import pandas as pd
import smtplib
from email.mime.text import MIMEText
import os

def envoyer_alertes(mode="console", from_email=None, password=None, to_email=None, subject="Alerte critique"):
    # Chargement du DataFrame
    csv_path = os.path.join(os.path.dirname(__file__), "DataFrame.csv")
    df = pd.read_csv(csv_path, encoding="utf-8")

    # Préparation des alertes
    print("\nDétection des vulnérabilités critiques (CVSS ≥ 8 et EPSS ≥ 0.7)")
    df["EPSS_score"] = pd.to_numeric(df["EPSS_score"], errors="coerce")
    df["CVSS_score"] = pd.to_numeric(df["CVSS_score"], errors="coerce")
    alertes = df[(df["CVSS_score"] >= 8) & (df["EPSS_score"] >= 0.7)]

    if alertes.empty:
        print("Aucune vulnérabilité critique détectée.")
        return False, ["Aucune vulnérabilité critique détectée."]

    messages = []
    stop_path = os.path.join(os.path.dirname(__file__), "stop_alerts.flag")

    for _, row in alertes.iterrows():
        if os.path.exists(stop_path):
            print("⛔ Envoi interrompu manuellement (fichier stop_alerts.flag détecté).")
            break

        produit = str(row.get("Produit", "N/A"))
        cve = str(row.get("CVE_ID", "N/A"))
        lien = str(row.get("Lien_bulletin", "N/A"))
        description = str(row.get("Description", "N/A"))
        cvss = str(row.get("CVSS_score", "N/A"))
        epss = str(row.get("EPSS_score", "N/A"))

        body = f"""Vulnérabilité critique détectée :

Produit       : {produit}
CVE ID        : {cve}
Score CVSS    : {cvss}
Score EPSS    : {epss}
Lien Bulletin : {lien}
Description   : {description.strip()[:300]}{'...' if len(description) > 300 else ''}
"""

        if mode == "console":
            print("\n" + "="*70)
            print(f"ALERTE : {cve}")
            print("-" * 70)
            print(body)
            print("="*70 + "\n")

        elif mode == "email":
            if not (from_email and password and to_email):
                print("Paramètres d'envoi d'email manquants.")
                return False, ["Erreur : paramètres email manquants."]

            msg = MIMEText(body)
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = f"{subject} : {cve}"

            try:
                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                server.login(from_email, password)
                server.sendmail(from_email, to_email, msg.as_string())
                server.quit()
                print(f"✅ Email envoyé pour {cve}")
            except Exception as e:
                print(f"❌ Échec d'envoi pour {cve} : {e}")

        messages.append(body)

    return True, messages


if __name__ == "__main__":
    print("\n ===== Système d’alerte de vulnérabilités critiques =====")
    choix = input("\nSouhaitez-vous : [1] afficher dans la console ou [2] envoyer par email ? \nTappez 1 ou 2 : ").strip()

    if choix == "1":
        envoyer_alertes(mode="console")
    elif choix == "2":
        from_email = input("Email expéditeur : ")
        password = input("Mot de passe d'application : ")
        to_email = input("Email destinataire : ")
        subject = input("Sujet (laisser vide pour 'Alerte critique') : ") or "Alerte critique"
        envoyer_alertes(mode="email", from_email=from_email, password=password, to_email=to_email, subject=subject)
    else:
        print("Choix invalide. Veuillez entrer 1 ou 2.")

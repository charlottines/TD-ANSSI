
# étape 6 : génération d'alertes et d'email

# Nous avons mis en place un système d’alerte pour identifier automatiquement les vulnérabilités critiques, en nous basant sur les critères suivants : 
# Score CVSS ≥ 8 ET EPSS ≥ 0.7
# Lorsqu’une vulnérabilité remplit ces deux conditions, un email d’alerte est envoyé et un print dans la console est fait
# Cela permet de cibler uniquement les failles à la fois critiques et avec une forte probabilité d’attaque effective, donc vraiment prioritaires 

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import smtplib
from email.mime.text import MIMEText

#chargement du DataFrame
csv_path = "DataFrame.csv"
df = pd.read_csv(csv_path, encoding="utf-8")


#fonction qui permet d'envoyer l'email
def send_email(to_email, subject, body):
    from_email = "votre_email@gmail.com"  #mettre l'email de l'envoyeur
    password = "mot_de_passe_application" #mettre le mdp application de l'envoyeur

    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()

#préparation des alertes
print("\n Simulation des alertes critiques par email")
df["EPSS_score"] = pd.to_numeric(df["EPSS_score"], errors="coerce")
df["CVSS_score"] = pd.to_numeric(df["CVSS_score"], errors="coerce")

#condition a respecter
alertes = df[(df["CVSS_score"] >= 8) & (df["EPSS_score"] >= 0.7)]

#affichage de l'alert dans la console
for i, row in alertes.iterrows():
    produit = row["Produit"]
    cve = row["CVE_ID"]
    lien = row["Lien_bulletin"]
    description = row["Description"]
    cvss = row["CVSS_score"]
    epss = row["EPSS_score"]

    print("\n" + "="*70)
    print(f"ALERTE : Vulnérabilité critique détectée")
    print("-" * 70)
    print(f"Produit       : {produit}")
    print(f"CVE ID        : {cve}")
    print(f"Score CVSS    : {cvss}")
    print(f"Score EPSS    : {epss}")
    print(f"Lien Bulletin : {lien}")
    print(f"Description   : {description.strip()[:300]}{'...' if len(description) > 300 else ''}")
    print("="*70 + "\n")

    
    #envoi alertes par email
    #send_email("votre_email@gmail.com", f"Alerte critique : {cve}", message)

    #ligne 66 à décommenter si on veut envoyer par email (aussi mettre la bonne adresse email et mdp lignes 20 et 21)
    




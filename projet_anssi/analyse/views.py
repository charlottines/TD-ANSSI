import os
import base64
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from io import BytesIO
from django.shortcuts import render
from django.conf import settings
from django.http import FileResponse, HttpResponse

CSV_PATH = os.path.join(settings.BASE_DIR, "..", "DataFrame.csv")
STATIC_DIR = os.path.join(settings.BASE_DIR, "static", "analyse")
def index(request):
    try:
        df = pd.read_csv(CSV_PATH)

        # Assure que la colonne date est bien traitée
        df["Date_publication"] = pd.to_datetime(df["Date_publication"], errors="coerce")

        # Trie par date décroissante + top 100
        df_sorted = df.sort_values("Date_publication", ascending=False).head(100)

        html_table = df_sorted.to_html(classes="table table-striped", index=False)

    except FileNotFoundError:
        html_table = "<div class='alert alert-danger'> Fichier CSV introuvable.</div>"

    return render(request, "analyse/index.html", {"table": html_table})

def graph(request):
    try:
        df = pd.read_csv(CSV_PATH)
    except FileNotFoundError:
        return render(request, "analyse/graph.html", {"error": "Fichier CSV introuvable"})

    os.makedirs(STATIC_DIR, exist_ok=True)
    graph_paths = []

    # 🔹 Graphe 1 : Répartition des scores CVSS
    plt.figure(figsize=(8, 4))
    df["Base_Severity"] = df["CVSS_score"].apply(lambda x: (
        "Critique" if x >= 9 else "Élevée" if x >= 7 else "Moyenne" if x >= 4 else "Faible"
    ) if pd.notna(x) else "Non défini")
    df["Base_Severity"].value_counts().plot(kind="bar", color="teal")
    plt.title("Distribution des niveaux de gravité CVSS")
    plt.xlabel("Gravité")
    plt.ylabel("Nombre de CVE")
    plt.tight_layout()
    path1 = os.path.join(STATIC_DIR, "cvss_hist.png")
    plt.savefig(path1)
    graph_paths.append("/static/analyse/cvss_hist.png")

    # 🔹 Graphe 2 : Répartition des types de bulletin
    plt.figure(figsize=(6, 4))
    df["Type"].value_counts().plot(kind="pie", autopct='%1.1f%%', colors=["#66c2a5", "#fc8d62"])
    plt.title("Types de bulletins (Avis vs Alerte)")
    plt.ylabel("")
    plt.tight_layout()
    path2 = os.path.join(STATIC_DIR, "type_pie.png")
    plt.savefig(path2)
    graph_paths.append("/static/analyse/type_pie.png")

    return render(request, "analyse/graph.html", {"graph_paths": graph_paths})

from django.http import FileResponse
import os
from django.conf import settings

def notebook_graphs(request):
    path = os.path.join(settings.BASE_DIR, "analyse", "static", "analyse", "graphs_from_notebook.html")
    return FileResponse(open(path, "rb"), content_type="text/html")

def ml_exported(request):
    try:
        path = os.path.join(settings.BASE_DIR, "analyse", "static", "analyse", "ml_result.html")
        return FileResponse(open(path, "rb"), content_type="text/html")
    except FileNotFoundError:
        return HttpResponse("<h2 style='color:red;'>Fichier Machine Learning introuvable.</h2>")
    
# views.py
def alerts_page(request):
    return render(request, "analyse/alerts.html")

from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
import pandas as pd
import smtplib
from email.mime.text import MIMEText

@csrf_exempt
def trigger_alerts(request):
    if request.method == "POST":
        try:
            df = pd.read_csv("DataFrame.csv", encoding="utf-8")
            df["EPSS_score"] = pd.to_numeric(df["EPSS_score"], errors="coerce")
            df["CVSS_score"] = pd.to_numeric(df["CVSS_score"], errors="coerce")

            alertes = df[(df["CVSS_score"] >= 8) & (df["EPSS_score"] >= 0.7)]

            from_email = "votre_email@gmail.com"
            password = "mot_de_passe_application"

            for _, row in alertes.iterrows():
                produit = row["Produit"]
                cve = row["CVE_ID"]
                lien = row["Lien_bulletin"]
                description = row["Description"]
                cvss = row["CVSS_score"]
                epss = row["EPSS_score"]

                body = f"""Alerte critique détectée :

Produit       : {produit}
CVE ID        : {cve}
Score CVSS    : {cvss}
Score EPSS    : {epss}
Lien Bulletin : {lien}
Description   : {description.strip()[:300]}{'...' if len(description) > 300 else ''}
                """

                msg = MIMEText(body)
                msg['From'] = from_email
                msg['To'] = "destinataire@email.com"
                msg['Subject'] = f"Alerte critique : {cve}"

                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                server.login(from_email, password)
                server.sendmail(from_email, "destinataire@email.com", msg.as_string())
                server.quit()

            return HttpResponse("✅ Alertes envoyées avec succès !")
        except Exception as e:
            return HttpResponse(f"<h3 style='color:red;'>Erreur : {str(e)}</h3>")
    return HttpResponse("Méthode non autorisée")
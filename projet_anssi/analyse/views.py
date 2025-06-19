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

STOP_SENDING = False

# views.py
def alerts_page(request):
    return render(request, "analyse/alerts.html")

from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.conf import settings
import pandas as pd
import smtplib
from email.mime.text import MIMEText
import os
import sys

# Ajouter TD-ANSSI/ dans les chemins accessibles à Python
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from alertes_mail import envoyer_alertes

@csrf_exempt
def trigger_alerts(request):
    global STOP_SENDING
    if request.method == "POST":
        from_email = request.POST.get("from_email")
        password = request.POST.get("password")
        to_email = request.POST.get("to_email")
        subject = request.POST.get("subject", "Alerte critique")

        if not all([from_email, password, to_email]):
            return HttpResponse("<div style='color:red;'> Erreur : tous les champs doivent être remplis.</div>")

        try:
            STOP_SENDING = False  # reset à chaque envoi
            success, messages = envoyer_alertes(
                mode="email",
                from_email=from_email,
                password=password,
                to_email=to_email,
                subject=subject
            )
            if not success:
                return HttpResponse("<div style='color:blue;'> Aucune vulnérabilité critique détectée.</div>")
            return HttpResponse("<div style='color:green;font-weight:bold;'> Alertes envoyées avec succès !</div>")
        except Exception as e:
            return HttpResponse(f"<div style='color:red;'> Erreur : {str(e)}</div>")

    return HttpResponse("<div style='color:orange;'> Méthode non autorisée</div>")



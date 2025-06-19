from django.contrib import admin
from django.urls import path
from analyse import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('graph/', views.graph, name='graph'),
    path("notebook-graphs/", views.notebook_graphs, name="notebook_graphs"),
    path("ml/", views.ml_exported, name="ml_exported"),
]

# 4. Fichier views.py (analyse/views.py)
import pandas as pd
from django.shortcuts import render
import matplotlib.pyplot as plt
import seaborn as sns
import os

from io import BytesIO
import base64

# Chemin vers le fichier CSV (adapte si besoin)
CSV_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'DataFrame.csv')


def index(request):
    df = pd.read_csv(CSV_PATH)
    df = df.fillna("Non disponible")
    table_html = df.head(100).to_html(classes="table table-striped", index=False)
    return render(request, "analyse/index.html", {"table": table_html})


def graph(request):
    df = pd.read_csv(CSV_PATH)
    df = df.fillna("Non disponible")
    df["Base_Severity"] = df["Base_Severity"].astype(str)

    # Création du graphique
    plt.figure(figsize=(8, 5))
    sns.countplot(data=df, x="Base_Severity", order=df["Base_Severity"].value_counts().index)
    plt.title("Distribution des niveaux de sévérité")
    plt.tight_layout()

    # Sauvegarde dans un buffer
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')

    return render(request, "analyse/graph.html", {"graphic": graphic})




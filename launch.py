import os
import subprocess
import webbrowser
import time

# Chemin absolu vers le dossier contenant manage.py
project_dir = os.path.join(os.path.dirname(__file__), "projet_anssi")

# Commande pour lancer le serveur Django
def run_django():
    subprocess.Popen(["python3", "manage.py", "runserver"], cwd=project_dir)

# Lancer le serveur
run_django()

# Attendre que le serveur démarre
time.sleep(2)

# Ouvrir automatiquement dans le navigateur
webbrowser.open("http://127.0.0.1:8000/")
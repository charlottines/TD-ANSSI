# Projet Data - Extraction et Enrichissement des Bulletins CERT-FR

## Fichier Fournis : 

### 1️) DataFrame.csv
DataFrame initial généré à partir des données fournis par le professeur (dossier "data_pour_TD_final")

### 2️) Projet-Data-Update.py
Fichier qui permet la mise à jour du DataFrame.csv à partir des informations du site de l'ANSSI

- On lit les flux RSS officiels :
    - https://www.cert.ssi.gouv.fr/avis/feed
    - https://www.cert.ssi.gouv.fr/alerte/feed
- On détecte les nouveaux bulletins publiés
- On les enrichit automatiquement :
    - Récupération des CVE
    - Détails MITRE + score EPSS FIRST
- On complète le DataFrame final (on met à jour DataFrame.csv avec les nouvelles données)

### 3️) alertes-mail.py

Ce script Python permet de détecter automatiquement les vulnérabilités critiques à partir d’un fichier CSV (DataFrame.csv) et de générer des alertes personnalisées, soit affichées dans la console, soit envoyées directement par email.
Le script identifie les vulnérabilités hautement critiques, en se basant sur deux indicateurs clés : CVSS_score ≥ 8 : gravité technique élevée ET EPSS_score ≥ 0.7 : forte probabilité d’exploitation réelle.
Cela permet de cibler uniquement les failles à la fois critiques et avec une forte probabilité d’attaque effective, donc vraiment prioritaires. 

Une fois le script lancé, l'utilisateur choisit le mode de notification :
- Affichage dans la console (1)
- Envoie par email (2)

Pour utiliser le 2eme mode :
- Activez l’authentification à deux facteurs dans Gmail
- Créez un mot de passe d'application
- Utilisez ce mot de passe à l’exécution du script

### 4) django.py
Ce script permet d’ouvrir automatiquement l’application Django et de lancer le serveur web en une seule commande, sans avoir à naviguer manuellement dans les dossiers. Il simplifie le démarrage du site pour visualiser les pages web et déclencher les alertes.

structure : 
projet_anssi/
├── analyse/                      ← App Django principale
│   ├── templates/analyse/       ← Fichiers HTML (frontend : visualisation, alertes, ML, etc.)
│   ├── static/analyse/          ← Fichiers statiques (CSS, images, scripts)
│   ├── views.py                 ← Logique backend (affichage, alertes, routes)
│   ├── urls.py                  ← Routes propres à l'app
├── projet_anssi/                ← Configuration principale du projet Django
│   ├── settings.py              ← Paramètres globaux (apps, chemins, sécurité)
│   ├── urls.py                  ← Routes globales du site 
├── manage.py                    ← Lancement classique du projet Django
├── launch.py                    ← Script personnalisé pour lancer rapidement l'app
├── db.sqlite3                   ← Base de données locale utilisée par Django

les pages :

- Accueil (/)
Page d’entrée du site, elle présente brièvement le projet et donne accès aux différentes sections.

- Visualisation (/visualisation)
Permet de consulter les graphiques et analyses statistiques extraits du fichier data-analysis.ipynb. Les visualisations sont interactives et accompagnées d’interprétations.

- Alertes (/alertes)
Page dédiée à l’envoi des alertes critiques par email. Un formulaire permet de saisir les identifiants Gmail et l’adresse du destinataire. Les alertes sont générées à partir du fichier DataFrame.csv.

- Machine Learning (/ml)
Affiche les résultats de l’étape 7 : modèles de machine learning appliqués aux vulnérabilités, avec validation, performances et interprétation.


  
### 5) data-analysis.html

Fichier html correspondant à notre Notebbok pour l'étape 5 qui contient l'interprétation et la visualisation de nos données avec les analyses et interprétations  de ces dernières. Chaque graphique est expliqué et interprété, afin de tirer des enseignements concrets pour la cybersécurité 

### 6) machine-learning-etape7.html

Fichier html correspondant à notre Notebbok pour l'étape 7 qui contient les différents modèles de Machine Learning ainsi que leurs explications, leurs analyses et leurs validations. 

## Pré-requis : 

### Commande à exécuter une première fois dans le Terminal (si pas déjà installé) : 
```bash
pip install feedparser
```

```bash
pip install django
```


## Structure du DataFrame final

| Colonne              | Description |
|----------------------|-------------|
| ID_ANSSI             | ID du bulletin |
| Titre_ANSSI          | Titre du bulletin |
| Type                 | Avis ou Alerte |
| Date_publication     | Date de publication |
| CVE_ID               | ID de la CVE |
| CVSS_score           | Score CVSS |
| Base_Severity        | Gravité (Base Severity) |
| CWE                  | Identifiant CWE |
| CWE_description      | Description du CWE |
| EPSS_score           | Score EPSS (FIRST) |
| Lien_bulletin        | Lien vers le bulletin détaillé |
| Description          | Description de la CVE |
| Editeur              | Éditeur concerné |
| Produit              | Produit concerné |
| Versions_affectees   | Versions affectées |



## Contributeurs 

XXX, XXX, XXX, XXX


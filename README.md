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
  
### 4) data-analysis.html

Fichier html correspondant à notre Notebbok pour l'étape 5 qui contient l'interprétation et la visualisation de nos données avec les analyses et interprétations  de ces dernières. Chaque graphique est expliqué et interprété, afin de tirer des enseignements concrets pour la cybersécurité 

### 5) machine-learning-etape7.html

Fichier html correspondant à notre Notebbok pour l'étape 7 qui contient les différents modèles de Machine Learning ainsi que leurs explications, leurs analyses et leurs validations. 

## Fonctionnement

### Commande à exécuter une première fois dans le Terminal (si pas déjà installé) : 
```bash
pip install feedparser
```

```bash
pip install django
```

### Etape 1 : 
S'assurer de bien avoir le fichier "Projet-Data-Update.py" dans le même répertoire que notre DataFrame.csv

### Etape 2 : 
Exécuter le fichier "Projet-Data.py" qui va récupérer les nouveaux bulletins sur le site de l'ANSSI et mettre à jour le DataFrame.csv en ajoutant ces nouveaux bulletins

### Etape 3 : 
Exécuter le fichier "alertes-mail.py" : des alertes vont apparaître dans la console pour indiquer les vulnérabilités critiques. Il y a également la possibilité d'envoyer ces alertes par email en décommentant la ligne 66 (send_email(...)), en configurant l'adresse email et le mdp de l'envoyeur (lignes 22 et 23) et en indiquant l'adresse email du receveur lors de l'appel de la fonction send_email(...) ligne 66

### Etape 4 : 
Regarder les pages html qui correspondent à nos fichiers .ipynb (nos Notebook Jupyter) des étapes 5 et 7, qui contiennent toute l’analyse des données de notre DataFrame.csv ainsi que des modèles de Machine Learning.




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


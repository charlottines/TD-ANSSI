# Projet Data - Extraction et Enrichissement des Bulletins CERT-FR

## Objectif

Constituer un DataFrame enrichi des bulletins de sécurité publiés par le CERT-FR (avis + alertes), contenant :
- le titre du bulletin
- la description
- la date de publication
- le lien vers le bulletin détaillé
- la liste des CVE associées
- pour chaque CVE : enrichissement via MITRE et FIRST

## Pipeline de traitement

### 1️⃣ Extraction initiale
Script : `Projet-Data-Local.py`

- On lit les bulletins fournis en local (dossier "data_pour_TD_final") :
    - dossiers Avis/, alertes/, mitre/, first/
- On génère un DataFrame de base : `DataFrame.csv`

### 2️⃣ Mise à jour automatique
Script : `Projet-Data-Update.py`

- On lit les flux RSS officiels :
    - https://www.cert.ssi.gouv.fr/avis/feed
    - https://www.cert.ssi.gouv.fr/alerte/feed
- On détecte les nouveaux bulletins publiés
- On les enrichit automatiquement :
    - Récupération des CVE
    - Détails MITRE + score EPSS FIRST
- On complète le DataFrame final (on le met à jour avec les nouvelles données)

### 3️⃣ Avantage

- Le DataFrame est **toujours à jour** en relançant simplement `Projet-Data-Update.py` régulièrement.

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


## Exécution

### Commande à exécuter la première fois dans le Terminal : 
```bash
pip install feedparser
```

### 1️⃣ Première exécution (extraction initiale) :
```bash
python Projet-Data-Local.py
```

### 2️⃣ Mises à jour régulières (nouveaux bulletins) :
```bash
python Projet-Data-Update.py
```

## Contributeurs 

Inès, Rhita, Léo, Anaëlle


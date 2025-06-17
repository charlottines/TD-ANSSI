import feedparser
import requests
import re
import time
import pandas as pd
import os

#lecture du DataFrame existant avec les données du prof

df_existing = pd.read_csv("DataFrame.csv", encoding="utf-8")
print(f"DataFrame existant : {df_existing.shape[0]} lignes")

#Etape 1 : Lecture flux RSS 

#liste des 2 flux à lire (avis et alertes)
flux_urls = [
    "https://www.cert.ssi.gouv.fr/avis/feed",
    "https://www.cert.ssi.gouv.fr/alerte/feed"
]

#on stocke les liens des bulletins pour l'étape 2
list_links = []
dict_bulletins = [] #pour stocker les infos pour le CSV

#On parcourt les 2 flux
for url in flux_urls:
    print(f"--- Flux : {url} ---")
    rss_feed = feedparser.parse(url)
    
    #Parcours de chaque bulletin
    for entry in rss_feed.entries:
        link = entry.link
        list_links.append(link)
        
        #Vérifie si ce bulletin est déjà dans le CSV
        if link in df_existing["Lien_bulletin"].values:
            print(f"Déjà dans le DataFrame : {link}")
            continue  #On ne le traite pas
        
        print("-" * 80)
        print(f"** Nouveau bulletin détecté ** :")
        print("Titre :", entry.title)
        print("Description:", entry.description)
        print("Date :", entry.published)
        print("Lien :", entry.link)
        print("-" * 80) #ligne de séparation pour la lisibilité
        
        type_bulletin = "Alerte" if "/alerte/" in link else "Avis"
        
        dict_bulletins.append({
            "Titre_ANSSI": entry.title,
            "Date_publication": entry.published,
            "Lien_bulletin": entry.link,
            "Type": type_bulletin,
            "Liste_CVE": []  #remplir en Etape 2
        })


#Etape 2 : Extraction des CVE 

print("\nExtraction CVE des nouveaux bulletins : \n")
for bulletin in dict_bulletins:
    link = bulletin["Lien_bulletin"]
    json_url = link + "json/"
    print("Lien JSON :", json_url)
    
    try:
        response = requests.get(json_url)
        response.raise_for_status()
        data = response.json()
        
        #par clés
        ref_cves = list(data.get("cves", []))
        cve_names = [cve["name"] for cve in ref_cves]
        
        #par regex (motif CVE-xxxx-yyyyy) quand c'est pas forcément mentionné dans les clés mais c'ets mentionné dans le texte
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list_json = list(set(re.findall(cve_pattern, str(data))))
        
        #fusion dans une liste sans doublons + maj du bulletin
        all_cves = list(set(cve_names + cve_list_json))
        bulletin["Liste_CVE"] = all_cves
        
        print("CVE trouvées :", all_cves)
    
    except Exception as e:
        print(f"Erreur récupération JSON : {e}")
    
    time.sleep(2)
    print("=" * 100)

#Etape 3 : Enrichissement avec API

enriched_cve_data = []

for bulletin in dict_bulletins:
    id_anssi = bulletin["Lien_bulletin"].split("/")[-2]
    titre_anssi = bulletin["Titre_ANSSI"]
    type_bulletin = bulletin["Type"]
    date_publication = bulletin["Date_publication"]
    lien_bulletin = bulletin["Lien_bulletin"]
    
    print(f"\n=== Traitement du bulletin : {id_anssi} ({len(bulletin['Liste_CVE'])} CVE) ===")
    
    for cve_id in bulletin["Liste_CVE"]:
        print(f"\nEnrichissement de {cve_id}...")
        
        # API MITRE
        try:
            url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            response_mitre = requests.get(url_mitre)
            response_mitre.raise_for_status()
            data_mitre = response_mitre.json()
            
            description = data_mitre["containers"]["cna"]["descriptions"][0]["value"]
            
            cvss_score = None
            base_severity = "Non disponible"

            metrics_list = data_mitre.get("containers", {}).get("cna", {}).get("metrics", [])

            if metrics_list:
                metrics = metrics_list[0]
                for version in ["cvssV3_1", "cvssV3_0", "cvssV2"]:
                    if version in metrics:
                        cvss_score = metrics[version].get("baseScore")
                        base_severity = metrics[version].get("baseSeverity", "Non disponible")
                        break

            
            cwe = "Non disponible"
            cwe_desc = "Non disponible"
            problemtype = data_mitre["containers"]["cna"].get("problemTypes", [])
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
            
            affected_products = data_mitre["containers"]["cna"].get("affected", [])
            
            if not affected_products:
                enriched_cve_data.append({
                    "ID_ANSSI": id_anssi,
                    "Titre_ANSSI": titre_anssi,
                    "Type": type_bulletin,
                    "Date_publication": date_publication,
                    "CVE_ID": cve_id,
                    "CVSS_score": cvss_score,
                    "Base_Severity": base_severity,
                    "CWE": cwe,
                    "CWE_description": cwe_desc,
                    "EPSS_score": None,
                    "Lien_bulletin": lien_bulletin,
                    "Description": description,
                    "Editeur": "Non disponible",
                    "Produit": "Non disponible",
                    "Versions_affectees": "Non disponible"
                })
            else:
                for product in affected_products:
                    vendor = product.get("vendor", "N/A")
                    product_name = product.get("product", "N/A")
                    versions = [v["version"] for v in product.get("versions", []) if v["status"] == "affected"]
                    versions_str = ", ".join(versions) if versions else "Non disponible"
                    
                    enriched_cve_data.append({
                        "ID_ANSSI": id_anssi,
                        "Titre_ANSSI": titre_anssi,
                        "Type": type_bulletin,
                        "Date_publication": date_publication,
                        "CVE_ID": cve_id,
                        "CVSS_score": cvss_score,
                        "Base_Severity": base_severity,
                        "CWE": cwe,
                        "CWE_description": cwe_desc,
                        "EPSS_score": None,
                        "Lien_bulletin": lien_bulletin,
                        "Description": description,
                        "Editeur": vendor,
                        "Produit": product_name,
                        "Versions_affectees": versions_str
                    })
        
        except Exception as e:
            print(f"Erreur enrichissement MITRE {cve_id} : {e}")
        
        #API FIRST (EPSS)
        try:
            url_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            response_epss = requests.get(url_epss)
            response_epss.raise_for_status()
            data_epss = response_epss.json()
            epss_data = data_epss.get("data", [])
            epss_score = epss_data[0]["epss"] if epss_data else None
        except Exception as e:
            print(f"Erreur enrichissement EPSS {cve_id} : {e}")
            epss_score = None
        
        #MAJ du score EPSS
        for row in enriched_cve_data:
            if row["CVE_ID"] == cve_id and row["ID_ANSSI"] == id_anssi:
                row["EPSS_score"] = epss_score
        
        time.sleep(1)

#Etape 4 : Fusion des dataframes et sauvegarde

df_new = pd.DataFrame(enriched_cve_data)
print(f"\nNouvelles lignes à ajouter : {df_new.shape[0]}")

#concaténation
df_final = pd.concat([df_existing, df_new], ignore_index=True)

# sauvegarde finale
df_final.to_csv("DataFrame.csv", index=False, encoding="utf-8")
print(f"DataFrame.csv mis à jour ! Total lignes : {df_final.shape[0]}")

import feedparser
import requests
import re
import time
import pandas as pd


#Etape1
#Liste des 2 flux à lire (avis et alertes)
flux_urls = [
    "https://www.cert.ssi.gouv.fr/avis/feed",
    "https://www.cert.ssi.gouv.fr/alerte/feed"
]

#On stocke les liens des bulletins pour l'étape 2
list_links = []

dict_bulletins = [] #pour stocker les infos pour le CSV

#On parcourt les 2 flux
for url in flux_urls:
    print(f"--- Flux : {url} ---")
    rss_feed = feedparser.parse(url)
    
    #Parcours de chaque bulletin
    for entry in rss_feed.entries:
        print("Titre :", entry.title)
        print("Description:", entry.description)
        print("Date :", entry.published)
        print("Lien :", entry.link)
        print("-" * 80) #ligne de séparation pour la lisibilité
        list_links.append(entry.link)

        type_bulletin = "Alerte" if "/alerte/" in entry.link else "Avis"

        dict_bulletins.append({
            "Titre_ANSSI": entry.title,
            "Date_publication": entry.published,
            "Lien_bulletin": entry.link,
            "Type": type_bulletin,
            "Liste_CVE": []  #on le remplira en étape 2
        })

        

#Etape2
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
        print("CVE référencées (clé cves) :", cve_names)

        #par regex (motif CVE-xxxx-yyyyy) quand c'est pas forcément mentionné dans les clés mais c'ets mentionné dans le texte
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list_json = list(set(re.findall(cve_pattern, str(data))))
        print("CVE trouvées dans JSON (regex) :", cve_list_json)

        #fusion dans une liste sans doublons
        all_cves = list(set(cve_names + cve_list_json))
        print("Liste totale CVE (sans doublons) :", all_cves)

        # mise à jour du bulletin
        bulletin["Liste_CVE"] = all_cves

        
    except Exception as e:
        print(f"Erreur lors de la récupération du JSON : {e}")
    
    time.sleep(2)
    print("=" * 100)



#Etape 3 : Enrichissement des CVE

enriched_cve_data = []  #future liste pour notre DataFrame final


for bulletin in dict_bulletins:
    id_anssi = bulletin["Lien_bulletin"].split("/")[-2]  #récupère l'ID depuis le lien
    titre_anssi = bulletin["Titre_ANSSI"]
    type_bulletin = bulletin["Type"]
    date_publication = bulletin["Date_publication"]
    lien_bulletin = bulletin["Lien_bulletin"]

    print(f"\n=== Traitement du bulletin : {id_anssi} ({len(bulletin['Liste_CVE'])} CVE) ===")

    for cve_id in bulletin["Liste_CVE"]:
        print(f"\nEnrichissement de {cve_id}...")

        #Appel API MITRE
        try:
            url_mitre = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            response_mitre = requests.get(url_mitre)
            response_mitre.raise_for_status()
            data_mitre = response_mitre.json()

            #Description
            description = data_mitre["containers"]["cna"]["descriptions"][0]["value"]

            #CVSS Score + Base Severity
            cvss_score = None
            base_severity = "Non disponible"
            try:
                metrics = data_mitre["containers"]["cna"]["metrics"][0]
                if "cvssV3_1" in metrics:
                    cvss_score = metrics["cvssV3_1"]["baseScore"]
                    base_severity = metrics["cvssV3_1"]["baseSeverity"]
                elif "cvssV3_0" in metrics:
                    cvss_score = metrics["cvssV3_0"]["baseScore"]
                    base_severity = metrics["cvssV3_0"]["baseSeverity"]
            except:
                pass

            #CWE
            cwe = "Non disponible"
            cwe_desc = "Non disponible"
            problemtype = data_mitre["containers"]["cna"].get("problemTypes", [])
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")

            #Produits affectés
            affected_products = data_mitre["containers"]["cna"].get("affected", [])
            
            #Cas où aucun produit n'est précisé
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
                    "EPSS_score": None,  #on va le remplir ensuite
                    "Lien_bulletin": lien_bulletin,
                    "Description": description,
                    "Editeur": "Non disponible",
                    "Produit": "Non disponible",
                    "Versions_affectees": "Non disponible"
                })

            else:
                #Une ligne par produit affecté
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
                        "EPSS_score": None,  #on va le remplir ensuite
                        "Lien_bulletin": lien_bulletin,
                        "Description": description,
                        "Editeur": vendor,
                        "Produit": product_name,
                        "Versions_affectees": versions_str
                    })

            time.sleep(1)  

        except Exception as e:
            print(f"Erreur enrichissement MITRE {cve_id} : {e}")
            time.sleep(1)

        #Appel API EPSS : on met à jour les lignes correspondantes
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

        #On met à jour toutes les lignes du CVE enrichi
        for row in enriched_cve_data:
            if row["CVE_ID"] == cve_id and row["ID_ANSSI"] == id_anssi:
                row["EPSS_score"] = epss_score

        time.sleep(1)  

print("\nEnrichissement terminé ! Nombre total de lignes enrichies :", len(enriched_cve_data))


#Etape 4 : Création du DataFrame à partir de enriched_cve_data
df = pd.DataFrame(enriched_cve_data)


#sauvegarde en CSV 
df.to_csv("DataFrame.csv", index=False, encoding="utf-8")

print("Fichier DataFrame.csv généré avec succès !")

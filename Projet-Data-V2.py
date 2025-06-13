import os
import json
import re
import pandas as pd

#fonctions pour un meilleur affichage
def clean_html(raw_html):
    if not isinstance(raw_html, str):
        return raw_html
    clean_re = re.compile('<[^>]+>')
    clean_text = re.sub(clean_re, '', raw_html)
    return clean_text.strip()

def format_description(desc, max_length=400):
    if not isinstance(desc, str):
        return desc
    desc = desc.replace('\n', ' ').replace('\r', ' ')
    desc = re.sub(r'\s+', ' ', desc)
    desc = desc.strip()
    if len(desc) > max_length:
        desc = desc[:max_length] + '...'
    return desc


#Étape 1 : Lecture des bulletins locaux (Avis + alertes)

folders = ["data_pour_TD_final/Avis", "data_pour_TD_final/alertes"]
dict_bulletins = []

for folder in folders:
    print(f"\n=== Lecture du dossier : {folder} ===\n")
    
    for filename in os.listdir(folder):
        file_path = os.path.join(folder, filename)
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        type_bulletin = "Alerte" if "alertes" in folder else "Avis"
     
        reference = data.get("reference", "N/A")

        titre = data.get("title", "N/A")
        description = format_description(clean_html(data.get("summary", "N/A")))
        date_pub = data.get("revisions", [{}])[0].get("revision_date", "N/A")   

        # reconstruction du lien
        if type_bulletin == "Avis":
            lien = f"https://www.cert.ssi.gouv.fr/avis/{reference}/"
        else:
            lien = f"https://www.cert.ssi.gouv.fr/alerte/{reference}/"
        
        
        
        print("Titre :", titre)
        print("Description :", description)
        print("Date :", date_pub)
        print("Lien :", lien)
        print("-" * 80)
        
        
        
        dict_bulletins.append({
            "Titre_ANSSI": titre,
            "Date_publication": date_pub,
            "Lien_bulletin": lien,
            "Type": type_bulletin,
            "Liste_CVE": [],
            "File_path": file_path  #utile pour étape 2
        })
        

#Étape 2 : Extraction des CVE

for bulletin in dict_bulletins:
    file_path = bulletin["File_path"]
    print("Lien JSON (local) :", file_path)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # par clés
    ref_cves = list(data.get("cves", []))
    cve_names = [cve["name"] for cve in ref_cves]
    print("CVE référencées (clé cves) :", cve_names)
    
    # par regex
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_list_json = list(set(re.findall(cve_pattern, str(data))))
    print("CVE trouvées dans JSON (regex) :", cve_list_json)
    
    # fusion sans doublons
    all_cves = list(set(cve_names + cve_list_json))
    print("Liste totale CVE (sans doublons) :", all_cves)
    
    # mise à jour du bulletin
    bulletin["Liste_CVE"] = all_cves
    
    print("=" * 100)



#Étape 3 : Enrichissement local avec mitre/ et first/ 

enriched_cve_data = []

for bulletin in dict_bulletins:
    id_anssi = os.path.basename(bulletin["File_path"])
    titre_anssi = bulletin["Titre_ANSSI"]
    type_bulletin = bulletin["Type"]
    date_publication = bulletin["Date_publication"]
    lien_bulletin = bulletin["Lien_bulletin"]
    
    print(f"\n=== Traitement du bulletin : {id_anssi} ({len(bulletin['Liste_CVE'])} CVE) ===")
    
    for cve_id in bulletin["Liste_CVE"]:
        print(f"\nEnrichissement de {cve_id}...")
        
        # MITRE
        try:
            with open(f"data_pour_TD_final/mitre/{cve_id}", 'r', encoding='utf-8') as f:
                data_mitre = json.load(f)
            
            description = data_mitre["containers"]["cna"]["descriptions"][0]["value"]
            
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
            
        
        # FIRST (EPSS)
        try:
            with open(f"data_pour_TD_final/first/{cve_id}", 'r', encoding='utf-8') as f:
                data_epss = json.load(f)
            
            if isinstance(data_epss, list):
                epss_score = data_epss[0]["epss"] if data_epss else None
            else:
                epss_data = data_epss.get("data", [])
                epss_score = epss_data[0]["epss"] if epss_data else None


        except Exception as e:
            print(f"Erreur enrichissement EPSS {cve_id} : {e}")
            epss_score = None
        
        # MAJ du score EPSS
        for row in enriched_cve_data:
            if row["CVE_ID"] == cve_id and row["ID_ANSSI"] == id_anssi:
                row["EPSS_score"] = epss_score

print("\nEnrichissement terminé ! Nombre total de lignes enrichies :", len(enriched_cve_data))



#Etape 4 : Création du DataFrame à partir de enriched_cve_data
df = pd.DataFrame(enriched_cve_data)

#sauvegarde en CSV 
df.to_csv("DataFrame-Local.csv", index=False, encoding="utf-8")

print("Fichier DataFrame-Local.csv généré avec succès !")
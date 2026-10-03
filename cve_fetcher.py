import requests
import json

def fetch_cve(cve_id):
    """Получает данные о CVE из NVD API."""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url, timeout=30)
    
    if response.status_code != 200:
        print(f"Ошибка: {response.status_code}")
        return None
    
    data = response.json()
    return data

def extract_cve_info(cve_data):
    """Извлекает ключевые поля из ответа NVD."""
    try:
        vuln = cve_data["vulnerabilities"][0]["cve"]
    except (KeyError, IndexError):
        return None

    # Описание (берём английское)
    description = ""
    for desc in vuln.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # CVSS (может быть v3.1, v3.0 или v2)
    cvss_score = None
    metrics = vuln.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_score = metrics[key][0]["cvssData"]["baseScore"]
            break

    # CWE
    cwe = None
    weaknesses = vuln.get("weaknesses", [])
    if weaknesses:
        cwe = weaknesses[0].get("description", [{}])[0].get("value")

    # Ссылки
    references = [ref.get("url") for ref in vuln.get("references", [])]

    return {
        "id": vuln.get("id"),
        "description": description,
        "cvss_score": cvss_score,
        "cwe": cwe,
        "references": references,
    }
if __name__ == "__main__":
    data = fetch_cve("CVE-2024-3094")
    info = extract_cve_info(data)
    print(json.dumps(info, indent=2, ensure_ascii=False))
import re

#! Code Generation
def extract_reqs(response_text):
    """
    Extracts dockerfile, SQL script, and requirements.txt content from LLM response.
    Cleans unnecessary strings like ``` etc. 
    Returns (dockerfile_content, sql_content, requirements_content)
    """
    dockerfile_match = re.search(r"```dockerfile\n(.*?)\n```", response_text, re.DOTALL)
    sql_match = re.search(r"```sql\n(.*?)\n```", response_text, re.DOTALL)
    requirements_match = re.search(r"```requirements\n(.*?)\n```", response_text, re.DOTALL)
    dockerfile_content = dockerfile_match.group(1).strip() if dockerfile_match else None
    sql_content = sql_match.group(1).strip() if sql_match else None
    requirements_content = requirements_match.group(1).strip() if requirements_match else None
    #dockerfile_content = clean_strings(dockerfile_dirty)
    #sql_content = clean_strings(sql_dirty)
    #requirements_content = clean_strings(requirements_dirty)
    return dockerfile_content, sql_content, requirements_content

def clean_code_response(response_text):
    #clean code responses from unnecessary strings that to prevent errors.
    response_text = re.sub(r"^```[\w]*\n", "", response_text)
    response_text = re.sub(r"\n```$", "", response_text)
    return response_text.strip()

#! Static Code Analysis
def normalize_tags(output):
    raw_matches = re.findall(r'\b[cC][wW][eE][\s:._-]?\s*(\d+)\b', output)
    return {f"CWE-{match.strip()}" for match in raw_matches}

def analyze_static_output(output):
    found_cwes = normalize_tags(output)  # to take cwes
    return ",".join(sorted(found_cwes)) if found_cwes else "None"  


def summarize_cwes(text: str) -> str:
    tags = normalize_tags(text)
    return ",".join(sorted(tags)) if tags else "None" 

'''def extract_sonar_tags(item):
    text = (item.get("message", "") + item.get("rule", "") +
            item.get("description", "") + item.get("vulnerabilityProbability", "")).lower()
    tags = set()
    tags.update(re.findall(r"CWE-\d+", text))

    keywords = {
        "xss": "CWE-79",
        "XSS": "CWE-79",
        "cross-site scripting": "CWE-79",
        "Cross-Site Scripting": "CWE-79",
        "sql injection": "CWE-89",
        "Sql Injection": "CWE-89",
        "command injection": "CWE-89",
        "Command Injection": "CWE-89",
        "csrf": "CWE-352",
        "CSRF": "CWE-352",
        "cross-site request forgery": "CWE-352",
        "Cross-Site Request Forgery": "CWE-352",
        "file upload": "CWE-434",
        "File Upload": "CWE-434",
        "unrestricted file upload": "CWE-434",
        "Unrestricted File Upload": "CWE-434",
        "dangerous file type": "CWE-434",
        "Dangerous Fle Type": "CWE-434",
        "ssrf": "CWE-918",
        "SSRF": "CWE-918",
        "server-side request forgery": "CWE-918",
        "Server-Side Request Forgery": "CWE-918",
        "url fetch": "CWE-918",

        }

    for key, cwe_code in keywords.items():
        if key in text:
            tags.add(cwe_code)

    return tags
'''


def extract_security_tags(item):
    text = (item.get("message", "") + item.get("rule", "") +
            item.get("description", "") + item.get("vulnerabilityProbability", "")).lower()
    tags = set()
    tags.update(re.findall(r"CWE-\d+", text))
    keywords = {
        "xss": "CWE-79",
        "XSS": "CWE-79",
        "cross-site scripting": "CWE-79",
        "Cross-Site Scripting": "CWE-79",
        "sql injection": "CWE-89",
        "Sql Injection": "CWE-89",
        "command injection": "CWE-89",
        "Command Injection": "CWE-89",
        "csrf": "CWE-352",
        "CSRF": "CWE-352",
        "cross-site request forgery": "CWE-352",
        "Cross-Site Request Forgery": "CWE-352",
        "file upload": "CWE-434",
        "File Upload": "CWE-434",
        "unrestricted file upload": "CWE-434",
        "Unrestricted File Upload": "CWE-434",
        "dangerous file type": "CWE-434",
        "Dangerous Fle Type": "CWE-434",
        "ssrf": "CWE-918",
        "SSRF": "CWE-918",
        "server-side request forgery": "CWE-918",
        "Server-Side Request Forgery": "CWE-918",
        "url fetch": "CWE-918",
        }
    for key, cwe_code in keywords.items():
        if key in text:
            tags.add(cwe_code)
    return tags

def filter_hotspots(hotspot_data):
    for h in hotspot_data.get("hotspots", []):
        file = h.get("component", "").split(":")[-1]
        line = h.get("line", "?")
        prob = h.get("vulnerabilityProbability", "UNKNOWN")
        category = h.get("securityCategory", "unknown")
        message = h.get("message", "").strip()
        return (f"- [{file}:{line}] {prob} ({category}): {message}")


def filter_issues(issue_data):
    if issue_data.get("total", 0) == 0:
        return "0"
    for issue in issue_data.get("issues", []):
        file = issue.get("component", "").split(":")[-1]
        line = issue.get("line", "?")
        severity = issue.get("severity", "UNKNOWN")
        rule = issue.get("rule", "unknown")
        message = issue.get("message", "").strip()
        return (f"- [{file}:{line}] {severity} ({rule}): {message}")

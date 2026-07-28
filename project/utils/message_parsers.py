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

def clean_code_response_old(response_text):
    #clean code responses from unnecessary strings that to prevent errors.
    response_text = re.sub(r"^```[\w],*\n", "", response_text)
    response_text = re.sub(r"\n```$", "", response_text)
    return response_text.strip()

def clean_code_response(response: str) -> str:
    if not response:
        return response
    # remove ```python ... ``` or ``` ... ``` blocks, keep only the content inside
    pattern = r"```(?:python)?\s*\n?(.*?)```"
    match = re.search(pattern, response, re.DOTALL)
    if match:
        return match.group(1).strip()
    # if no code block markers found, return as-is after stripping
    return response.strip()

#! Static Code Analysis
def normalize_tags_old(output):
    raw_matches = re.findall(r'\b[cC],[wW],[eE],[\s:._-],?\s*(\d+)\b', output)
    return {f"CWE-{match.strip()}" for match in raw_matches}

def normalize_tags(output):
    if not output:
        return set()
    # matches: CWE-89, CWE-605, cwe-89 etc.
    raw_matches = re.findall(r'[Cc][Ww][Ee][-\s:]+(\d+)', output)
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
    for h in hotspot_data.get("hotspots", [],):
        file = h.get("component", "").split(":")[-1],
        line = h.get("line", "?")
        prob = h.get("vulnerabilityProbability", "UNKNOWN")
        category = h.get("securityCategory", "unknown")
        message = h.get("message", "").strip()
        return (f"- [{file}:{line}], {prob} ({category}): {message}")


def filter_issues(issue_data):
    if issue_data.get("total", 0) == 0:
        return "0"
    for issue in issue_data.get("issues", [],):
        file = issue.get("component", "").split(":")[-1],
        line = issue.get("line", "?")
        severity = issue.get("severity", "UNKNOWN")
        rule = issue.get("rule", "unknown")
        message = issue.get("message", "").strip()
        return (f"- [{file}:{line}], {severity} ({rule}): {message}")


BURP_TYPE_TO_CWE = {
1048832	:["CWE-77","CWE-78","CWE-116"],
1049088	:["CWE-89","CWE-94","CWE-116"],
1049104	:["CWE-89","CWE-94","CWE-116"],
1049216	:["CWE-10","CWE-11 "],
1049344	:["CWE-22","CWE-23","CWE-35","CWE-36"],
1049600	:["CWE-611"],
1049856	:["CWE-90","CWE-116"],
1050112	:["CWE-94","CWE-116","CWE-159","CWE-643"],
1050368	:["CWE-91","CWE-116","CWE-159","CWE-611","CWE-776"],
1050624	:["CWE-11"],
1050704	:["CWE-284"],
1050880	:["CWE-650"],
1051136	:["CWE-610","CWE-918"],
1051392	:["CWE-22","CWE-23","CWE-35","CWE-36"], 
1051648	:["CWE-94","CWE-116","CWE-159"], 
1051904	:["CWE-94","CWE-95","CWE-116"], 
1052160	:["CWE-94","CWE-95","CWE-116"], 
1052416	:["CWE-94","CWE-95","CWE-116"], 
1052432	:["CWE-94","CWE-95","CWE-116"], 
1052448	:["CWE-116","CWE-159","CWE-917"], 
1052672	:["CWE-94","CWE-95","CWE-116"], 
1052800	:["CWE-94","CWE-95","CWE-116"], 
1052928	:["CWE-96","CWE-116","CWE-159"], 
1053184	:["CWE-502"], 
2097408	:["CWE-79","CWE-80","CWE-116","CWE-159"], 
2097472	:["CWE-444"], 
2097473	:["CWE-444"], 
2097536	:["CWE-436"],
2097664	:["CWE-113"], 
2097920	:["CWE-79","CWE-80","CWE-116","CWE-159"],
2097928	:["CWE-116","CWE-159"], 
2097936	:["CWE-79","CWE-80","CWE-116","CWE-159"], 
2097937	:["CWE-79","CWE-80","CWE-116","CWE-159"], 
2097938	:["CWE-79","CWE-80","CWE-116","CWE-159"], 
2097942	:["CWE-1321"], 
2097952	:["CWE-94","CWE-95","CWE-116"], 
2097953	:["CWE-94","CWE-95","CWE-116"], 
2097954	:["CWE-94","CWE-95","CWE-116"], 
2097960	:["CWE-16"], 
2097968	:["CWE-89","CWE-116","CWE-159"], 
2097969	:["CWE-89","CWE-116","CWE-159"], 
2097970	:["CWE-89","CWE-116","CWE-159"], 
2097984	:["CWE-345","CWE-346","CWE-441"], 
2097985	:["CWE-345","CWE-346","CWE-441"], 
2097986	:["CWE-345","CWE-346","CWE-441"], 
2098000	:["CWE-22","CWE-73"], 
2098001	:["CWE-22","CWE-73"], 
2098002	:["CWE-22","CWE-73"], 
2098016	:["CWE-79","CWE-116","CWE-159"], 
2098017	:["CWE-79","CWE-116","CWE-159"], 
2098018	:["CWE-79","CWE-116","CWE-159"], 
2098032	:["CWE-79","CWE-116","CWE-159"],
2098033	:["CWE-79","CWE-116","CWE-159"], 
2098034	:["CWE-79","CWE-116","CWE-159"], 
2098176	:["CWE-942"], 
2098432	:["CWE-942"], 
2098435	:["CWE-79","CWE-80","CWE-116","CWE-159"], 
2098436	:["CWE-79","CWE-80","CWE-116","CWE-159"], 
2098437	:["CWE-116","CWE-159"], 
2098438	:[],
2098439	:["CWE-693","CWE-1021"], 
2098440	:["CWE-116"], 
2098441	:[],
2098448	:[],
2098449	:[],
2098450	:["CWE-200"], 
2098451	:["CWE-200"],
2098452	:["CWE-352"], 
2098688	:["CWE-942"], 
2098689	:["CWE-942"], 
2098690	:["CWE-942"],
2098691	:["CWE-942"], 
2098768	:[],
2098944	:["CWE-352"], 
2099200	:["CWE-93","CWE-159"], 
2099456	:["CWE-345","CWE-347"], 
2099457	:["CWE-345"], 
2099458	:[],
2099459	:[],
2099460	:[],
2099461	:[],
3145984	:["CWE-319"], 
3146240	:["CWE-918","CWE-406"], 
3146256	:["CWE-918","CWE-406"], 
3146272	:["CWE-16","CWE-406"], 
4194560	:["CWE-16","CWE-213"], 
4194576	:["CWE-16"], 
4194592	:["CWE-16"], 
4194816	:["CWE-204"], 
4195072	:["CWE-598"], 
4195328	:["CWE-598"], 
4195456	:["CWE-598"], 
4195584	:["CWE-16"], 
4195840	:["CWE-642"], 
4196096	:["CWE-776"], 
4196352	:["CWE-698"], 
4196608	:["CWE-502"], 
4196864	:["CWE-16"], 
4197120	:["CWE-20","CWE-116"],
4197376	:["CWE-20","CWE-116"],
4197632	:["CWE-20"],
4197888	:["CWE-20"],
4198144	:["CWE-436"],
5243008	:["CWE-1104"],
5243136	:["CWE-601"],
5243137	:["CWE-601"],
5243152	:["CWE-601"],
5243153	:["CWE-601"],
5243154	:["CWE-601"],
5243392	:["CWE-614"],
5243648	:["CWE-16"],
5243904	:["CWE-200"],
5244160	:["CWE-829"],
5244416	:["CWE-16"],
5244672	:["CWE-200","CWE-384","CWE-598"],
5244928	:["CWE-200"],
5245184	:["CWE-287"],
5245312	:["CWE-434"],
5245344	:["CWE-693","CWE-1021"],
5245360	:["CWE-16"],
5245440	:["CWE-16"],
5245696	:["CWE-565","CWE-829"],
5245697	:["CWE-565","CWE-829"],
5245698	:["CWE-565","CWE-829"],
5245952	:["CWE-116"],
5245953	:["CWE-116"],
5245954	:["CWE-116"],
5246208	:["CWE-400"],
5246209	:["CWE-400"],
5246210	:["CWE-400"],
5246464	:["CWE-20"],
5246465	:["CWE-20"],
5246466	:["CWE-20"],
5246720	:["CWE-20"],
5246721	:["CWE-20"],
5246722	:["CWE-20"],
5246976	:["CWE-20"], 
5246977	:["CWE-20"],
5246978	:["CWE-20"],
5246979	:["CWE-73","CWE-20"],
5246980	:["CWE-73","CWE-20"],
5247232	:["CWE-20"],
5247233	:["CWE-20"],
5247234	:["CWE-20"],
5247488	:["CWE-20"],
5247489	:["CWE-20"],
5247490	:["CWE-20"],
5247744	:["CWE-73","CWE-20"],
5247745	:["CWE-73","CWE-20"],
5248000	:["CWE-233","CWE-20"],
5248001	:["CWE-233","CWE-20"],
5248256	:["CWE-73","CWE-20"],
5248257	:["CWE-73","CWE-20"],
6291584	:["CWE-15","CWE-497"],
6291632	:["CWE-18","CWE-200","CWE-388","CWE-540","CWE-541","CWE-615"],
6291672	:["CWE-530"],
6291712	:["CWE-538","CWE-548"],
6291968	:["CWE-200"],
6292224	:["CWE-200"],
6292480	:["CWE-200"],
6292736	:["CWE-200","CWE-388"], 
6292816	:["CWE-200","CWE-388"],
6292992	:["CWE-200"],
6293248	:["CWE-200"],
6293504	:["CWE-200"],
6293760	:["CWE-200"],
6293761	:["CWE-200"],
7340288	:["CWE-524 ","CWE-525"], 
7340544	:["CWE-310 ","CWE-311"],
8388864	:["CWE-436"],
8389120	:["CWE-16","CWE-436"],
8389376	:["CWE-16","CWE-436"],
8389632	:["CWE-16","CWE-436"],
8389888	:["CWE-16"],
16777472 :	["CWE-295","CWE-326","CWE-327"], 
16777728 :	["CWE-326"],
16777984 :	["CWE-523"],
16778240 :	["CWE-16","CWE-319"],
16778496 :	["CWE-912"]
}
#* Those configurations are set in burpsuite configuration library manually
#* According to issue list above.
CWE_TO_BURP_CONFIG = {
    #! A01:Broken Access Control - done
    "CWE-22":"CWE-22-Path-Traversal",
    "CWE-23":"CWE-23-Relative-Path-Traversal",
    "CWE-35":"CWE-23-Relative-Path-Traversal",  
    "CWE-200":"CWE-200-Exposure-Sensitive-Information",
    "CWE-284":"CWE-284-Broken-Access-Control",
    "CWE-352":"CWE-352-Cross-Site-Request-Forgery",
    "CWE-441":"CWE-441-Confused-Deputy",
    "CWE-538":"CWE-538-Insertion-Directory",
    "CWE-540":"CWE-540-Sensitive-Information-Source-Code",
    "CWE-548":"CWE-538-Insertion-Directory", 
    "CWE-601":"CWE-601-Open-Redirect",      

    #! A02:Security Misconfiguration - done
    "CWE-11":"CWE-11-Dotnet-misconfig",
    "CWE-16":"CWE-16-Configuration",
    "CWE-611":"CWE-611-XML-Restriction",
    "CWE-614":"CWE-614-Cookie-Attribute",
    "CWE-776":"CWE-776-XML-Entity-Expansion",
    "CWE-942":"CWE-942-Cross-Domain-Policy",



    #! A03:Software Supply Chain - done
    "CWE-1104":"CWE-1104-Unmaintained-Third-Party",

    #! A04:Cryptographic Failures - done 
    "CWE-319":"CWE-319-Cleartext-Transmission-Sensitive-Information",
    "CWE-326":"CWE-326-Inadequate-Encryption-Strength",
    "CWE-327":"CWE-327-Broken-Cryptographic-Algorithm",
    "CWE-347":"CWE-347-Improper-Verification-Cryptographic-Signature",
    "CWE-523":"CWE-523-Unprotected-Transport-Credentials",

    #! A05:Injection - done
    "CWE-77":  "CWE-77-78-Command-Injection",   
    "CWE-78":  "CWE-77-78-Command-Injection",
    "CWE-79":  "CWE-79-Cross-site-scripting",
    "CWE-80":  "CWE-80-XSS",
    "CWE-90":  "CWE-90-LDAP-Injection",
    "CWE-91":  "CWE-91-XML-Injection",
    "CWE-93":  "CWE-93-CRLF-SMTP-Injection",
    "CWE-94":  "CWE-94-Command-Injection",
    "CWE-95":  "CWE-95-Eval-Injection",
    "CWE-96":  "CWE-96-SSI-Injection",
    "CWE-97":  "CWE-97-SSI-Injection",
    "CWE-113": "CWE-113-HTTP-Header-Injection",
    "CWE-116": "CWE-116-Improper-Encoding-Escaping",
    "CWE-159": "CWE-159-Improper-Handling-Elements",  # burada bir sıkıntı yaşadık taramalar hata vermeden takılı kalıyor 12k paket atmış
    "CWE-20":  "CWE-20-Improper-Input",
    "CWE-643": "CWE-643-Xpath-Injection",
    "CWE-917": "CWE-917-Expression-Language-Injection", # bu test edilmedi
    "CWE-610": "CWE-610-Out-of-band-resource",
    "default": "Audit checks - all except time-based detection methods",

    #! A06: Insecure Design - done
    "CWE-73": "CWE-73-External-Control-Filenamepath",
    "CWE-311":  "CWE-311-Missing-Encryption-Sensitivedata",
    "CWE-434":  "CWE-434-File-Upload",
    "CWE-436":  "CWE-436-Interpretation-Conflict",
    "CWE-444":  "CWE-444-HTTP-Request-Smuggling",
    "CWE-525":  "CWE-525-Browser-Cache-Sensitive-Info",
    "CWE-598":  "CWE-598-HTTP-Request-Sensitive-Query",
    "CWE-642":  "CWE-642-Critical-State-Control",
    "CWE-693":  "CWE-693-Protection-Mechanism-Failure",
    "CWE-1021": "CWE-693-Protection-Mechanism-Failure",


    #! A07: Authentication Failures - done
    "CWE-287":  "CWE-287-Improper Authentication",   
    "CWE-295":  "CWE-295-Improper-Certificate-Validation",
    "CWE-346":  "CWE-346-Origin-Validation-Error",
    "CWE-384":  "CWE-384-Session-Fixation",
    
    
    #! A08: Software or Data Integrity Failures - done
    "CWE-345":  "CWE-345-Insufficient-Verification-Data-Authenticity",
    "CWE-502":  "CWE-502-Deserialization-Untrusted-Data",
    "CWE-565":  "CWE-565-Cookies-Without-Validation",
    "CWE-829":  "CWE-829-Untrusted-Control-Sphere"
    #! A09: Security Logging and Alerting Failures

    #! A10: Mishandling of Exceptional Conditions
}



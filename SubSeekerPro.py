import subprocess, sys, json, logging, os
from concurrent.futures import ThreadPoolExecutor
try:
    from terminaltables import AsciiTable
    from colorama import Fore, Back, Style, init
    import builtwith
    import requests
except ModuleNotFoundError as e:
    print("Installing Python Modules...", end="\n")
    try:
        os.system("pip install -r requirements.txt")
    except:
       print("Error! Try install manual dependencies using \n -> pip install -r requirements.txt")
else:
    init(autoreset=True)


COLORS = {
    'header': Fore.CYAN + Style.BRIGHT,
    'subdomain': Fore.YELLOW,
    'tech': Fore.GREEN,
    'exploit': Fore.MAGENTA,
    'error': Fore.RED,
    'summary': Back.BLUE + Fore.WHITE + Style.BRIGHT,
    'info': Fore.BLUE,
    'ssl': Fore.LIGHTWHITE_EX
}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')



HEADER_ART = """
  _________              _____.__                
 /   _____/ ____   _____/ ____\__|______   ____  
 \_____  \ /  _ \ /    \   __\|  \_  __ \_/ __ \ 
 /        (  <_> )   |  \  |  |  ||  | \/\  ___/ 
/_______  /\____/|___|  /__|  |__||__|    \___  >
        \/            \/                      \/                                                   
"""

def run_subprocess(command):
    """Utility function to run subprocess commands and capture output."""
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"{COLORS['error']}Subprocess error: {e.stderr}")
        return None
    except Exception as e:
        logging.error(f"{COLORS['error']}Error running subprocess: {e}")
        return None

def find_subdomains(domain):
    """Use sublist3r to find subdomains."""
    logging.info(f"{COLORS['header']}Finding subdomains for {domain}")
    output_file = f"{domain}_subdomains.txt"
    command = ['sublist3r', '-d', domain, '-o', output_file]
    run_subprocess(command)
    try:
        with open(output_file, 'r') as file:
            subdomains = [line.strip() for line in file]
        return subdomains
    except FileNotFoundError:
        logging.error(f"{COLORS['error']}Sublist3r output file not found.")
        return []

def choose_scan_depth():
    """Let the user choose the Nmap scan depth."""
    print(f"{COLORS['info']}Choose Nmap Scan Depth:")
    print("1. Quick Scan (-F)")
    print("2. Version Detection (-sV)")
    print("3. Aggressive Scan (-A)")
    choice = input("Enter choice (1-3): ").strip()
    return {
        "1": "-F",
        "2": "-sV",
        "3": "-A"
    }.get(choice, "-F")

def scan_with_nmap(domain, scan_depth):
    """Scan a domain with Nmap."""
    logging.info(f"{COLORS['info']}Scanning {domain} with Nmap using {scan_depth} option...")
    command = ['nmap', scan_depth, domain]
    output = run_subprocess(command)
    return output

def ssl_scan(domain):
    """Perform an SSL scan on a domain."""
    logging.info(f"{COLORS['info']}Performing SSL scan on {domain}...")
    command = ['sslscan', domain]
    output = run_subprocess(command)
    return output

def search_exploits(technology):
    """Search for exploits matching a specific technology."""
    command = ['searchsploit', technology, '--json']
    output = run_subprocess(command)
    if output:
        try:
            data = json.loads(output)
            return data.get('RESULTS_EXPLOIT', [])
        except json.JSONDecodeError as e:
            logging.error(f"{COLORS['error']}Failed to parse SearchSploit output: {e}")
    return []

def find_tech_stack(domain):
    """Identify the technology stack of a given domain."""
    try:
        if not domain.startswith(('http://', 'https://')):
            # HSTS option default is active
            domain = 'https://' + domain
        return builtwith.parse(domain)
    except Exception as e:
        logging.error(f"{COLORS['error']}Error identifying technology stack: {e}")
        return {}

def process_domain(domain, scan_depth):
    """Process each domain: Nmap scan, SSL scan, tech stack identification, and exploit search."""
    scan_results = scan_with_nmap(domain, scan_depth)
    ssl_results = ssl_scan(domain)
    technologies = find_tech_stack(domain)
    tech_names = {name for _, names in technologies.items() for name in names}
    exploits = []
    for tech in tech_names:
        exploits.extend(search_exploits(tech))
    return domain, scan_results, ssl_results, tech_names, exploits

def main(domain):
    """Main function to orchestrate the entire process."""
    print(COLORS['header'] + HEADER_ART)
    subdomains = find_subdomains(domain)
    if not subdomains:
        logging.info(f"{COLORS['error']}No subdomains found. Exiting...")
        return
    logging.info(f"{COLORS['summary']}Found {len(subdomains)} subdomains for {domain}")

    scan_depth = choose_scan_depth()

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_subdomain = {executor.submit(process_domain, subdomain, scan_depth): subdomain for subdomain in subdomains}

        for future in future_to_subdomain:
            subdomain = future_to_subdomain[future]
            try:
                _, scan_results, ssl_results, tech_names, exploits = future.result()
                logging.info(f"{COLORS['subdomain']}[{subdomain}] - {COLORS['tech']}Tech: {', '.join(tech_names)} - {COLORS['exploit']}Exploits: {len(exploits)} found")
                if scan_results:
                    print(COLORS['info'] + f"Nmap Scan Results for {subdomain}:\n{scan_results}")
                if ssl_results:
                    print(COLORS['ssl'] + f"SSL Scan Results for {subdomain}:\n{ssl_results}")
                if exploits:
                    table_data = [['Title', 'Type']] + [[exp['Title'], exp['Type']] for exp in exploits]
                    table = AsciiTable(table_data)
                    print(COLORS['exploit'] + f"Exploits for {subdomain}:\n{table.table}")
            except Exception as exc:
                logging.error(f"{COLORS['error']}{subdomain} generated an exception: {exc}")

if __name__ == "__main__":
    nmap_check = True if os.path.exists('/usr/bin/nmap') else False
    sublist3r_check = True if os.path.exists('/usr/bin/sublist3r') else False

    ## Only verify in Linux OS
    if not nmap_check or not sublist3r_check:
        try:
            if not nmap_check:
                logging.info(f"{COLORS['info']} Installing nmap...")
                os.system('sudo apt-get install nmap')
            if not sublist3r_check:
                logging.info(f"{COLORS['info']} Installing sublist3r...")
                # Problaly don't work in linux distros, only works in Kali
                os.system('sudo apt-get install sublist3r')
        except:
            logging.error(f"{COLORS['error']}Depedence: any depedences not found in system and cannot install")

    if len(sys.argv) != 2:
        logging.error(f"{COLORS['error']}Usage: python {sys.argv[0]} <domain>")
        sys.exit(1)

    ## Check Python version
    if not sys.version_info[0] > 3:
        logging.error(f"{COLORS['error']}Python version is not compatible with this script.")
        
    domain = sys.argv[1]
    main(domain)

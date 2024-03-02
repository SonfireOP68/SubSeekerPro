import subprocess
import sys
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from terminaltables import AsciiTable
from colorama import Fore, init
import builtwith

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_subprocess(command):
    """Utility function to run subprocess commands and capture output."""
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stderr:
            logging.error(f"Subprocess error: {result.stderr}")
        return result.stdout
    except Exception as e:
        logging.error(f"Error running subprocess: {e}")
        return None

def find_subdomains(domain):
    """Use sublist3r to find subdomains."""
    logging.info(f"Finding subdomains for {domain}")
    output_file = f"{domain}_subdomains.txt"
    command = ['sublist3r', '-d', domain, '-o', output_file]
    run_subprocess(command)
    with open(output_file, 'r') as file:
        subdomains = [line.strip() for line in file]
    return subdomains

def scan_with_nmap(domain):
    """Scan a domain with Nmap."""
    logging.info(f"Scanning {domain} with Nmap...")
    command = ['nmap', '-Pn', '-F', domain]
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
            logging.error(f"Failed to parse SearchSploit output: {e}")
    return []

def find_tech_stack(domain):
    """Identify the technology stack of a given domain."""
    if not domain.startswith(('http://', 'https://')):
        domain = 'http://' + domain
    return builtwith.parse(domain)

def process_domain(domain):
    """Process each domain: Nmap scan, tech stack identification, and exploit search."""
    scan_results = scan_with_nmap(domain)
    technologies = find_tech_stack(domain)
    tech_names = {name for _, names in technologies.items() for name in names}
    exploits = []
    for tech in tech_names:
        exploits.extend(search_exploits(tech))
    return domain, scan_results, tech_names, exploits

def main(domain):
    """Main function to orchestrate the entire process."""
    subdomains = find_subdomains(domain)
    logging.info(f"Found {len(subdomains)} subdomains for {domain}")

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_subdomain = {executor.submit(process_domain, subdomain): subdomain for subdomain in subdomains}

        for future in future_to_subdomain:
            subdomain = future_to_subdomain[future]
            try:
                _, scan_results, tech_names, exploits = future.result()
                logging.info(f"[{subdomain}] - Tech: {', '.join(tech_names)} - Exploits: {len(exploits)} found")
                if scan_results:
                    print(Fore.CYAN + f"Nmap Scan Results for {subdomain}:\n{scan_results}")
                if exploits:
                    table_data = [['Title', 'Type']] + [[exp['Title'], exp['Type']] for exp in exploits]
                    table = AsciiTable(table_data)
                    print(Fore.YELLOW + f"Exploits for {subdomain}:\n{table.table}")
            except Exception as exc:
                logging.error(f"{subdomain} generated an exception: {exc}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        logging.error(f"{Fore.RED}Usage: python {sys.argv[0]} <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    main(domain)

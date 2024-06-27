import argparse
import requests
import json
import time
from datetime import datetime
from tqdm import tqdm
import pandas as pd
from colorama import init, Fore, Style
import re

def print_ascii_art():
    ascii_art = """
░░░▄▀▀▀▄░░░░░░░░░░░░░▄▀▀▀▄░░░░░░
░░░█░░░██░░░░░░░░░░░░█░░░█░░░░░░
░░░▀█░░░█░░░░░░░░░░░█▀░░░█░░░░░░
░░░░█░░░▀█▄▄▄▄░▄▄▄▄▄█░░░█▀░░░░░░
░░░░█░░░░██░░▀█▀░░██▀░░▄█░░░░░░░
░░░░░█░░░▀█░░░█░░░██░░░█░░░░░░░░
░░░░░█░░░░█░░░█░░░█░░░░█░░░░░░░░
░░░░▄█░░░░█▄░▄█▄░▄█░░▄█▀▀██▄░░░░
░░░░█░░░░░░▀▀▀▀▀▀▀░░░█▄░░░░█▄░░░
░░░░█░░░░░░░░░░░░░░░░▀█▄▄░░░█░░░
░░░░█░░░░░░░░░░░░░░░░░░░░░░▄█░░░
░░░░█░░░░░░░░░░░░░░░░░░░░░░█░░░░
░░░░░█░░░░░░░░░░░░░░░░░░░▄██░░░░
░░░░░▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄██▀▀▀░░░░░░
░░░░░░█████████████▀░░░░░░░░░░░░
░░░░░░██▀▀█████████░░░░░░░░░░░░░                                                                              
    """
    print(ascii_art)
    
def query_hudsonrock(email):
    url = 'https://cavalier.hudsonrock.com/api/json/v2/search-by-login?sample=true&sortby=date_uploaded'
    headers = {
        'Host': 'cavalier.hudsonrock.com',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Content-Type': 'application/json;charset=utf-8',
        'api-key': 'ROCKHUDSONROCK',
        'Origin': 'https://cavalier.hudsonrock.com',
        'Referer': 'https://cavalier.hudsonrock.com/docs',
    }
    data = {'login': email}

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error querying HudsonRock for {email}: {e}")
        return None
    pass

def extract_information(response, email):
    if not response:
        return None

    extracted_data = []

    for entry in response.json():
        data = {
            'email': email if email else '',  # Include the email address in the data
            'stealer_family': entry.get('stealer_family', ''),
            'date_uploaded': entry.get('date_uploaded', ''),
            'date_compromised': entry.get('date_compromised', ''),
            'computer_name': entry.get('computer_name', ''),
            'operating_system': entry.get('operating_system', ''),
            'antiviruses': entry.get('antiviruses', []),
        }

        credentials = entry.get('credentials', [])
        if credentials:
            data['url'] = credentials[0].get('url', '')
            data['domain'] = credentials[0].get('domain', '')

        employee_session_cookies = entry.get('employee_session_cookies', [])
        if employee_session_cookies:
            data['employee_session_cookies'] = ", ".join(
                f"{cookie.get('url', '')} ({cookie.get('expiry', '')})"
                for cookie in employee_session_cookies
            )

        extracted_data.append(data)

    return extracted_data
    pass

def is_expired(cookie_expiry_time):
    if cookie_expiry_time:
        expiry_datetime = datetime.strptime(cookie_expiry_time, "%Y-%m-%dT%H:%M:%S.%fZ")
        return expiry_datetime < datetime.now()
    return False
    pass

def read_email_addresses(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]
    pass

def process_email_addresses(file_path, verbose=False):
    email_addresses = read_email_addresses(file_path)
    results = []

    for email in tqdm(email_addresses, desc=f"\033[1m\033[91mProcessing\033[0m", unit="email"):
        print(f"Querying HudsonRock for {email}")
        response = query_hudsonrock(email)

        if response:
            extracted_data = extract_information(response, email)
            if extracted_data:
                if verbose:
                    print_information(extracted_data)
                results.extend(extracted_data)

        # Throttle requests to one request every 10 seconds
        time.sleep(10)

    return results
    pass

def save_to_excel(results, excel_file):
    if not results:
        print("No results to save.")
        return

    df = pd.DataFrame(results)

    # Rename columns for better readability
    column_mapping = {
        'email': 'Email Address',
        'stealer_family': 'Stealer Family',
        'date_uploaded': 'Date Uploaded',
        'date_compromised': 'Date Compromised',
        'computer_name': 'Computer Name',
        'operating_system': 'Operating System',
        'antiviruses': 'Antiviruses',
        'employee_session_cookies': 'Employee Session Cookies',
    }

    df = df.rename(columns=column_mapping)

    # Exclude 'url' and 'domain' columns
    df = df.drop(['url', 'domain'], axis=1, errors='ignore')

    df.to_excel(excel_file, index=False)
    print(f"{Fore.GREEN}{Style.BRIGHT}Results saved to {excel_file}.{Style.RESET_ALL}")
    pass

def print_information(data):
    if not data:
        print("User not found.")
        return

    for entry in data:
        print("\n--- Entry ---")
        print(f"{Style.BRIGHT}Stealer Family:{Style.RESET_ALL} {entry.get('stealer_family', '')}")
        print(f"{Style.BRIGHT}Date Uploaded:{Style.RESET_ALL} {entry.get('date_uploaded', '')}")
        print(f"{Style.BRIGHT}Date Compromised:{Style.RESET_ALL} {entry.get('date_compromised', '')}")
        print(f"{Style.BRIGHT}Computer Name:{Style.RESET_ALL} {entry.get('computer_name', '')}")
        print(f"{Style.BRIGHT}Operating System:{Style.RESET_ALL} {entry.get('operating_system', '')}")
        print(f"{Style.BRIGHT}Antiviruses:{Style.RESET_ALL} {', '.join(entry.get('antiviruses', []))}")

        employee_session_cookies = entry.get('employee_session_cookies', '')
        if employee_session_cookies:
            print(f"{Style.BRIGHT}Employee Session Cookies:{Style.RESET_ALL} {employee_session_cookies}")
    pass

def main():

    print_ascii_art()
    print(f"{Fore.WHITE}{Style.BRIGHT}[+] Rock 'N' Roll{Style.RESET_ALL}\n")

    args = argparser()
    print(f"{Fore.YELLOW}{Style.BRIGHT}[+] Running HudsonRock E-Mail Search!{Style.RESET_ALL}")
    if args.file_path:
        results = process_email_addresses(args.file_path, verbose=args.verbose)

        # Save results to Excel file
        save_to_excel(results, args.houtput)

        print(f"\n{Fore.GREEN}{Style.BRIGHT}Processing complete!{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.RED}No email addresses file provided. HudsonRock Email Search will not run.{Style.RESET_ALL}")


def get_token(domain):
    url = f"https://2.intelx.io:443/phonebook/search?k={args.apikey}"
    headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:101.0) Gecko/20100101 Firefox/101.0",
                     "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                     "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "https://phonebook.cz",
                     "Dnt": "1", "Referer": "https://phonebook.cz/", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors",
                     "Sec-Fetch-Site": "cross-site", "Te": "trailers"}
    if args.email:
        json_data = {"maxresults": 10000, "media": 0, "target": 2, "term": domain, "terminate": [None], "timeout": 20}
    if args.domain:
        json_data = {"maxresults": 10000, "media": 0, "target": 1, "term": domain, "terminate": [None], "timeout": 20}
    if args.links:
        json_data = {"maxresults": 10000, "media": 0, "target": 3, "term": domain, "terminate": [None], "timeout": 20}
    response = requests.post(url, headers=headers, json=json_data)
    key = response.text
    status = response.status_code
    if status == 402:
        exit(f'{Fore.RED}[!] Your IP is rate limited. Try switching your IP address then re-run.{Style.RESET_ALL}')
    else:
        return key

def make_request(key):
    key = json.loads(key)['id']
    url = f"https://2.intelx.io:443/phonebook/search/result?k={args.apikey}&id={key}&limit=1000000"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:101.0) Gecko/20100101 Firefox/101.0",
        "Accept": "*/*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
        "Origin": "https://phonebook.cz", "Dnt": "1", "Referer": "https://phonebook.cz/", "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "cross-site", "Te": "trailers"}
    response = requests.get(url, headers=headers)
    items = response.text
    status = response.status_code
    if status == 402:
        exit(f'{Fore.RED}[!] Your IP is rate limited. Try switching your IP address then re-run.{Style.RESET_ALL}')
    else:
        return items

    ioutput = args.ioutput

def parse_items(items, ioutput, verbose=False, email=False, domain=False, links=False):
    ioutput = args.ioutput
    email = args.email
    domain = args.domain
    link = args.links
    items = json.loads(items)['selectors']
    url_pattern = re.compile(r'(http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&\/~\(\)+#-]*[\w@?:;^=%&\/~+#-])')

    if email:
        data = []
        for item in items:
            item_value = item['selectorvalue']
            if verbose:
                print(item_value)
            data.append(item_value)

        df = pd.DataFrame(data, columns=['Emails'])

        df.to_excel(ioutput, index=False)
        print(f'\n{Fore.GREEN}{Style.BRIGHT}[+] Done! Saved to {ioutput}')
    if domain:
        data = []
        for item in items:
            item_value = item['selectorvalue']
            if verbose:
                print(item_value)
            data.append(item_value)

        df = pd.DataFrame(data, columns=['Subdomains'])

        df.to_excel(ioutput, index=False)
        print(f'\n{Fore.GREEN}{Style.BRIGHT}[+] Done! Saved to {ioutput}')
    if link:
        data = []
        for item in items:
            original_url = item['selectorvalue']
            matched_url = url_pattern.search(original_url)
            stripped_url = url_pattern.sub('', original_url).strip()
            if stripped_url:
                matched_url = matched_url.group()
                if verbose:
                    print(stripped_url)
                data.append([matched_url, stripped_url])

        df = pd.DataFrame(data, columns=['URL', 'Username:Password'])

        
        df.to_excel(ioutput, index=False)
        print(f'\n{Fore.GREEN}{Style.BRIGHT}[+] Done! Saved to {ioutput}')



def argparser():
    parser = argparse.ArgumentParser(description="Rock 'N' Roll")
    parser.add_argument("-f","--file-path", nargs='?', help="Path to the text file containing email addresses for HudsonRock and COMB Search")
    parser.add_argument("-ho","--houtput", help="Path to the HudsonRock Search results output Excel file (default: HudsonRock-results.xlsx)", default="HudsonRock-results.xlsx")
    parser.add_argument("-co","--coutput", help="Path to the COMB Search results output Excel file (default: COMB-results.xlsx)", default="COMB-results.xlsx")
    parser.add_argument("-io","--ioutput", help="Path to the IntelX (Phonebook.cz) Search results output Excel file (default: IntelX-results.xlsx)", default="IntelX-results.xlsx")
    parser.add_argument("--verbose", help="Display detailed results in the terminal", action="store_true")
    parser.add_argument("-e", "--email", help="Search all emails for provided domain.")
    parser.add_argument("-k", "--apikey", help="Search all emails for provided domain.")
    parser.add_argument("-d", "--domain", help="Search all subdomains for provided domain.")
    parser.add_argument("-l", "--links", help="Search all links for provided domain. (Sometimes includes cleartext passwords from stealer logs)")
    return parser.parse_args()

def query_comb(email, verbose=False):
    print(f"\nQuerying COMB database for {email}")

    url = f"https://api.proxynova.com/comb?query={email}"

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        lines = data.get("lines", [])

        # Filter lines that match the input email
        matching_lines = [line for line in lines if email in line]

        if matching_lines:
            results = []
            for matching_line in matching_lines:
                if verbose:
                    print(matching_line)
                results.append(matching_line)
            return results
        else:
            print(f"No matching records found for email: {email}")
            return None
    else:
        print(f"Error querying {email}: {response.status_code}")
        print(response.text)
        return None

def run_comb(file_path, verbose=False):
    
    args = argparser()
    cofile = args.coutput

    print(f"{Fore.MAGENTA}{Style.BRIGHT}[+] Running COMB (Combination Of Many Breaches) Leaked Password Search!{Style.RESET_ALL}")
    if args.file_path:
        email_addresses = read_email_addresses(file_path)
        results_list = []
        for email in tqdm(email_addresses, desc=f"\033[1m\033[91mProcessing\033[0m", unit="email"):
            results = query_comb(email, args.verbose)
            if results:
                results_list.extend(results)

        if results_list:
            df = pd.DataFrame(results_list, columns=["Username:Password"])
            df.to_excel(cofile, index=False)
            print(f"{Fore.GREEN}{Style.BRIGHT}Results saved to {cofile}. {Style.RESET_ALL}")

            print(f"\n{Fore.GREEN}{Style.BRIGHT}Processing complete!{Style.RESET_ALL}\n")
        else:
            print(f"{Fore.RED}No results to save.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No email addresses file provided. COMB (Combination Of Many Breaches) Leaked Password Search will not run.{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
    args = argparser()
    print(f"{Fore.BLUE}{Style.BRIGHT}[+] Running IntelX Domain Search!{Style.RESET_ALL}")

    if args.apikey:
        if args.email or args.domain or args.links:
            if args.email:
                key = get_token(args.email)
            if args.domain:
                key = get_token(args.domain)
            if args.links:
                key = get_token(args.links)

            emails = make_request(key)
            
            parse_items(emails, args.ioutput, args.verbose)
        else:
            print(f"{Fore.RED}No domain provided. Phonebook.cz Email Checker will not run.{Style.RESET_ALL}\n")
    else:
            print(f"{Fore.RED}IntelX api key not provided.{Style.RESET_ALL}\n")

    run_comb(args.file_path, args.verbose)

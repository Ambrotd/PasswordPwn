import requests
import hashlib
import sys
import argparse
import re
import platform
import os
from bs4 import BeautifulSoup
import random

'''Using GET https://api.pwnedpasswords.com/range/{first 5 hash chars} the k-model allows anonymity as the full hash 
is not getting out of your computer '''


class Color:
    def __init__(self, system_type):
        if system_type == "Windows":
            self.HEADER = ''
            self.OKBLUE = ''
            self.OKGREEN = ''
            self.WARNING = ''
            self.FAIL = ''
            self.ENDC = ''
            self.BOLD = ''
            self.UNDERLINE = ''
            self.BLACK = ''
            self.RED = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.BLUE = ''
            self.MAGENTA = ''
            self.CYAN = ''
            self.WHITE = ''
            self.RESET = ''
        else:
            self.HEADER = '\033[95m'
            self.OKBLUE = '\033[94m'
            self.OKGREEN = '\033[92m'
            self.WARNING = '\033[93m'
            self.FAIL = '\033[91m'
            self.ENDC = '\033[0m'
            self.BOLD = '\033[1m'
            self.UNDERLINE = '\033[4m'
            self.BLACK = '\u001b[30m'
            self.RED = '\u001b[31m'
            self.GREEN = '\u001b[32m'
            self.YELLOW = '\u001b[33m'
            self.BLUE = '\u001b[34m'
            self.MAGENTA = '\u001b[35m'
            self.CYAN = '\u001b[36m'
            self.WHITE = '\u001b[37m'
            self.RESET = '\u001b[0m'


system = platform.system()
col = Color(system)
API_URL = 'https://api.pwnedpasswords.com/range/'


def clean():
    if system == "Windows":
        os.system("cls")
    if system == "Linux":
        os.system("clear")


def sha1_hash(to_hash):
    return hashlib.sha1(to_hash.encode('utf-8')).hexdigest().upper()


def passwd_api_check(password):
    sha1 = sha1_hash(password)
    hash_to_api, hash_to_check = sha1[0:5], sha1[5:]
    check_url = API_URL + hash_to_api
    r = requests.get(check_url)
    if r.status_code != 200:
        raise RuntimeError(f'Api is down, error {r.status_code}; Check the api')
    hash_generator = (i.split(':') for i in r.text.splitlines())
    for h, count in hash_generator:
        if h == hash_to_check:
            return count
    return 0


def email_tor_check(email):
    url = 'http://pwndb2am4tzkvold.onion.ws'
    email_list = []
    if '@' in email:
        user = email.split('@')[0]
        domain = email.split('@')[1]
    else:
        user = email
        domain = '%'
    if len(user) == 0:
        user = '%'

    data = {'luser': user, 'domain': domain, 'luseropr': 1, 'domainopr': 1, 'submitform': 'em'}
    try:
        r = requests.post(url, timeout=10, data=data)
        if r.status_code != 200:
            raise RuntimeError(f'Service is down, error {r.status_code}; Check the service')
    except:
        print(f"{col.WARNING}The onion service is down we cannot check cleartext passwords now for email: {email}")
        return 0
    response = r.text
    if 'Array' not in response:
        return 0
    leaked_data = response.split("Array")[2:]
    for i in leaked_data:
        # luser = ''
        # ldomain = ''
        # lpassword = ''
        # lemail = ''
        luser = re.search(r'(?<=luser] => )[^\s]*', i).group(0)
        ldomain = re.search(r'(?<=domain] => )[^\s]*', i).group(0)
        lpassword = re.search(r'(?<=password] => )[^\s]*', i).group(0)
        email = f'{luser}@{ldomain}'
        if luser:
            email_list.append({"email": email, "passwd": lpassword})
    return print_leaks(email_list, email)


def print_leaks(email_list, email_base):
    if email_list:
        for dic in email_list:
            print(f'The email {col.WARNING}[+]->> {col.RED}{dic["email"]}{col.ENDC} has been leaked with the '
                  f'password {col.WARNING}[+]--> {col.RED}{dic["passwd"]}{col.ENDC}')
    else:
        print(
            f'The email {col.WARNING}[+]->> {col.GREEN}{email_base}{col.ENDC} {col.CYAN}Doesn\'t have any cleartext '
            f'passwords found!{col.ENDC}')


def print_passwd(count, password):
    if count != 0:
        print(
            f'{col.WARNING}Your password {col.RED}{password}{col.WARNING} has been leaked {col.RED}{count}{col.WARNING} times{col.ENDC}')
    else:
        print(
            f'{col.GREEN}Your password {col.WARNING}{password}{col.GREEN} has not been compromised yet!{col.ENDC}')


def get_proxy_list():
    try:
        print(f"{col.FAIL}The proxy is not yet implemented")
        sys.exit()
        proxy_list = []
        header = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36',
            'Accept-Language': 'en-US,en;q=0.5'}
        s = requests.Session()
        s.headers.update(header)
        web = s.get("https://hidemy.name/es/proxy-list/?maxtime=800&type=s#list")
        soup = BeautifulSoup(web.content, 'html.parser')
        table_data = soup.find_all('td')
        ip_list = table_data[7::7]
        port_list = table_data[8::7]
        for i in range(len(ip_list)):
            proxy = ip_list[i].string + ':' + port_list[i].string
            proxy_list.append(proxy)
        return proxy_list
    except:
        print("The proxy failed!")
        sys.exit()


def check_firefox(email_in, proxy_list=[], hidden=0):
    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    email = re.match(regex, email_in)
    if email:
        email = email.group(0)
        url = 'https://monitor.firefox.com'
        s = requests.Session()
        try:
            if hidden:
                if len(proxy_list) == 1:
                    proxy_index = 0
                else:
                    proxy_index = random.randint(0, len(proxy_list) - 1)
                proxy = {"http": proxy_list[proxy_index], "https": proxy_list[proxy_index]}
            else:
                proxy = ''
            r = s.get(url, timeout=12, proxies=proxy)
            if r.status_code != 200:
                raise Exception(f'Service is down, error {r.status_code}; Check the service')
            soup = BeautifulSoup(r.text, "html.parser")
            csrf = soup.find('input', {'name': '_csrf'})['value']
            email_hash = sha1_hash(email)
            data = {"_csrf": csrf, "pageToken": "", "scannedEmailId": 2, "email": "", "emailHash": email_hash}
            firefox_leaks = s.post(url + "/scan", data, timeout=12, proxies=proxy)
            if firefox_leaks.status_code != 200:
                raise Exception(f'Service is down, error {r.status_code}; Check the service')
            soup1 = BeautifulSoup(firefox_leaks.text, "html.parser")
            list_breaches = soup1.findAll("div", {"class": "breach-info-wrapper"})
            clean_breaches = []
            for breach in list_breaches:
                data = breach.div.findAll('span')
                for i in data:
                    clean_breaches.append(i.string)
            s.close()
            return print_firefox_leaks(clean_breaches, email)

        except:
            if hidden:
                # print(proxy_list)
                proxy_list.pop(proxy_index)
                check_firefox(email, proxy_list, hidden)
            else:
                print(f"{col.FAIL}Too many request to firefox from that IP Address try using a proxy or VPN")

    else:
        print("Database breach by name are only available for complete email search. Try again with the full email"
              "ex:username@domain.xyz")


def print_firefox_leaks(clean_breaches, email):
    if clean_breaches is None or len(clean_breaches) == 0:
        print(f'The email {col.GREEN}{email}{col.ENDC} is not on firefox records')
    else:
        print(f'The email {col.RED}{email}{col.ENDC} was leaked in:')
        for i in range(int(len(clean_breaches) / 5)):
            print(
                f"\t{col.MAGENTA}{clean_breaches[5 * i]}{col.ENDC}. The {clean_breaches[5 * i + 1]} on {col.BLUE}{clean_breaches[5 * i + 2]}{col.ENDC} the {clean_breaches[5 * i + 3]}  {col.YELLOW}{clean_breaches[5 * i + 4]}")


def main():
    parser = argparse.ArgumentParser()
    banner = ''' 

8888888b.                                                888 8888888b.  888       888 888b    888 
888   Y88b                                               888 888   Y88b 888   o   888 8888b   888 
888    888                                               888 888    888 888  d8b  888 88888b  888 
888   d88P  8888b.  .d8888b  .d8888b  888  888  888  .d88888 888   d88P 888 d888b 888 888Y88b 888 
8888888P"      "88b 88K      88K      888  888  888 d88" 888 8888888P"  888d88888b888 888 Y88b888 
888        .d888888 "Y8888b. "Y8888b. 888  888  888 888  888 888        88888P Y88888 888  Y88888 
888        888  888      X88      X88 Y88b 888 d88P Y88b 888 888        8888P   Y8888 888   Y8888 
888        "Y888888  88888P'  88888P'  "Y8888888P"   "Y88888 888        888P     Y888 888    Y888 
                                                                                                  
            {}Check if your passwd or email have been leaked without compromising them{}
                                By {}Ambrotd{}
    
    '''.format(col.WARNING, col.ENDC, col.RED, col.ENDC)
    print(f'{col.OKBLUE}{banner}{col.ENDC}')
    parser.add_argument("-p", "--passwords", nargs='+', type=str, dest='passwords',
                        help="Insert the passwords to check separated by space")
    parser.add_argument("-e", "--email", nargs='+', type=str, dest='emails',
                        help="Insert the emails to check separated by space."
                             " It can check just the username, the complete email or your domain with @domain.xyz")
    parser.add_argument('-P', '--proxy', action='store_true',
                        help="When set tries some free proxies to avoid limitations")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.proxy:
        proxy_list = get_proxy_list()
    else:
        proxy_list = []

    if type(args.passwords) == list:
        for password in args.passwords:
            print_passwd(passwd_api_check(password), password)

    elif args.passwords:
        print_passwd(passwd_api_check(args.passwords), args.passwords)

    if type(args.emails) == list:
        for email in args.emails:
            check_firefox(email, proxy_list, args.proxy)
            email_tor_check(email)

    elif args.emails:
        check_firefox(args.emails, proxy_list, args.proxy)
        email_tor_check(args.emails)


if __name__ == '__main__':
    clean()
    sys.exit(main())

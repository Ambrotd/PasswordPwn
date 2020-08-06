import requests
import hashlib
import sys
import argparse
import re
import platform
import os

'''
Using GET https://api.pwnedpasswords.com/range/{first 5 hash chars} the k-model allows anonymity as the full hash is not getting
out of your computer
'''


class Color:
    def __init__(self, system):
        if system == "Windows":
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


def passwd_api_check(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
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
    if '@' in email:
        user = email.split('@')[0]
        domain = email.split('@')[1]
    else:
        user = email
        domain = '%'
    if len(user) == 0:
        user = '%'

    data = {'luser': user, 'domain': domain, 'luseropr': 1, 'domainopr': 1, 'submitform': 'em'}
    r = requests.post(url, data=data)
    if r.status_code != 200:
        raise RuntimeError(f'Service is down, error {r.status_code}; Check the service')
    response = r.text
    if 'Array' not in response:
        return 0
    leaked_data = response.split("Array")[2:]
    email_list = []
    for i in leaked_data:
        luser = ''
        ldomain = ''
        lpassword = ''
        lemail = ''
        luser = re.search(r'(?<=luser] => )[^\s]*', i).group(0)
        ldomain = re.search(r'(?<=domain] => )[^\s]*', i).group(0)
        lpassword = re.search(r'(?<=password] => )[^\s]*', i).group(0)
        email = f'{luser}@{ldomain}'
        if luser:
            email_list.append({"email": email, "passwd": lpassword})
    return email_list


def print_leaks(email_list):
    for dic in email_list:
        print(f'The email {col.WARNING}[+]->> {col.RED}{dic["email"]}{col.ENDC} has been leaked with the '
              f'password {col.WARNING}[+]--> {col.RED}{dic["passwd"]}{col.ENDC}')


def print_passwd(count,password):
    if count != 0:
        print(
            f'{col.WARNING}Your password {col.RED}{password}{col.WARNING} has been leaked {col.RED}{count}{col.WARNING} times{col.ENDC}')
    else:
        print(
            f'{col.GREEN}Your password {col.WARNING}{password}{col.GREEN} has not been compromised yet!{col.ENDC}')


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
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if type(args.passwords) == list:
        for password in args.passwords:
            print_passwd(passwd_api_check(password),password)

    elif args.passwords:
        print_passwd(passwd_api_check(args.passwords),args.passwords)

    if type(args.emails) == list:
        for email in args.emails:
            leaks = email_tor_check(email)
            if leaks:
                print_leaks(leaks)
            else:
                print(
                    f'The email {col.WARNING}[+]->> {col.GREEN}{email}{col.ENDC} {col.CYAN}It\'s safe no leaks found!{col.ENDC}')
    elif args.emails:
        leaks = email_tor_check(args.emails)
        if leaks:
            print_leaks(leaks)
        else:
            print(
                f'The email {col.WARNING}[+]->> {col.GREEN}{args.emails}{col.ENDC} {col.CYAN}It\'s safe no leaks found!{col.ENDC}')


if __name__ == '__main__':
    clean()
    sys.exit(main())

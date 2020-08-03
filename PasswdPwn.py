import requests
import hashlib
import sys
import argparse
import re

'''
Using GET https://api.pwnedpasswords.com/range/{first 5 hash chars} the k-model allows anonymity as the full hash is not getting
out of your computer
'''
class bColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLACK = '\u001b[30m'
    RED = '\u001b[31m'
    GREEN = '\u001b[32m'
    YELLOW = '\u001b[33m'
    BLUE = '\u001b[34m'
    MAGENTA = '\u001b[35m'
    CYAN = '\u001b[36m'
    WHITE = '\u001b[37m'
    RESET = '\u001b[0m'

API_URL = 'https://api.pwnedpasswords.com/range/'


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

    data = {'luser': user, 'domain': domain, 'luseropr' : 1,'domainopr': 1,'submitform': 'em'}
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
        print(f'The email {bColors.WARNING}[+]->> {bColors.RED}{dic["email"]}{bColors.ENDC} has been leaked with the '
              f'password {bColors.WARNING}[+]--> {bColors.RED}{dic["passwd"]}{bColors.ENDC}')


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
    
    '''.format(bColors.WARNING, bColors.ENDC, bColors.RED, bColors.ENDC)
    print(f'{bColors.OKBLUE}{banner}{bColors.ENDC}')
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
            count = passwd_api_check(password)
            if count != 0:
                print(f'{bColors.WARNING}Your password {bColors.RED}{password}{bColors.WARNING} has been leaked {bColors.RED}{count}{bColors.WARNING} times{bColors.ENDC}')
            else:
                print(f'{bColors.GREEN}Your password {bColors.WARNING}{password}{bColors.GREEN} has not been compromised yet!{bColors.ENDC}')
    elif args.passwords:
        count = passwd_api_check(args.passwords)
        if count != 0:
            print(
                f'{bColors.WARNING}Your password {bColors.RED}{args.passwords}{bColors.WARNING} has been leaked {bColors.RED}{count}{bColors.WARNING} times{bColors.ENDC}')

        else:
            print(f'{bColors.GREEN}Your password {bColors.WARNING}{args.passwords}{bColors.GREEN} has not been compromised yet!{bColors.ENDC}')
    if type(args.emails) == list:
        for email in args.emails:
            leaks = email_tor_check(email)
            if leaks:
                print_leaks(leaks)
            else:
                print(f'The email {bColors.WARNING}[+]->> {bColors.GREEN}{email}{bColors.ENDC} {bColors.CYAN}It\'s safe no leaks found!{bColors.ENDC}')
    elif args.emails:
        leaks = email_tor_check(args.emails)
        if leaks:
            print_leaks(leaks)
        else:
            print(f'The email {bColors.WARNING}[+]->> {bColors.GREEN}{args.emails}{bColors.ENDC} {bColors.CYAN}It\'s safe no leaks found!{bColors.ENDC}')


if __name__ == '__main__':
    sys.exit(main())
import requests
import hashlib
import sys

'''
Using GET https://api.pwnedpasswords.com/range/{first 5 hash chars} the k-model allows anonymity as the full hash is not getting
out of your computer
'''
API_URL = 'https://api.pwnedpasswords.com/range/'

def passwd_api_check(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    hash_to_api, hash_to_check = sha1[0:5], sha1[5:]
    check_url = API_URL + hash_to_api
    r = requests.get(check_url)
    if r.status_code != 200:
        raise RuntimeError(f'Api is down, error {r.status_code}; Check the api')
    #print(f'first 5->{hash_to_api} last ->{hash_to_check}')
    #print(r.text)
    hash_generator =(i.split(':') for i in r.text.splitlines())
    for h, count in hash_generator:
        if h == hash_to_check:
            return count
    return 0



count=passwd_api_check('testpass')
print(count)


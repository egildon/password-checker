
'''This is a password checker app'''
import hashlib
#import unicode

import requests
import sys

hashes_dict = {}

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char # K hashed password SHA1
    res = requests.get(url)
    #print(dir(res))
    if res.status_code != 200:
        #print (res.status_code)
        raise RuntimeError(f'Error getting: {res.status_code} check the API and try again.')
    return res


def pwned_api_check(password):
    hashedpw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()#must pass an encoded and formatted string
    print(hashedpw)
    head6_char, tail6_char = hashedpw[:5], hashedpw[5:]#must be exactly 5 characters
    print(f'Head: {head6_char}, Tail: {tail6_char}')
    response = request_api_data(head6_char)
    #print(response)
    return get_password_leaks_ct(response, hashedpw)
#TODO:see if this shows up

def read_resp(response):
    print(response.text)

def get_password_leaks_ct(hashes, hash_to_check):
    print(hashes.text)
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for hashx, count in hashes:
        if hashx == hash_to_check:
            
            return count
    return 0

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'Match! Your Password has been compromised {count} many times.')
            print('You should change your password!')
        else:
            print('Youre all good! Party on!')
        return 'DONE!'

if __name__ == '__main__':
    main(sys.argv[1:])

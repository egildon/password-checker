'''This is a password checker app'''
import sys
import hashlib
#import time
import requests
import flask
#TODO: add GUI
import sqlalchemy

test_password = '123456'
test_hash = hashlib.sha1(test_password.encode('utf-8')).hexdigest().upper() #must pass an encoded and formatted string
test_header = ':'
test_footer = ' 2'
test_hash_list = (test_header + test_hash + test_footer)
test_count = 2
#"".join(test_hash_list)
# print(test_hash_list)


def request_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char[:5]}' # K hashed password SHA1
    res = requests.get(url)
    #print(dir(res))
    if res.status_code != 200:
        #print (res.status_code)
        raise RuntimeError(f'Error getting: {res.status_code} check the API and try again.')
    return res


def pwned_api_check(password):
    user_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()#must pass an encoded and formatted string
    head5_char, tail5_char = user_hash[:5], user_hash[5:] #must be exactly 5 characters
    #strips head and tail characters from returned factory
    response = request_api_data(head5_char)
    user_hash2 = user_hash[:35]
    print(response)
    return get_password_leaks_ct(response, user_hash2)
# def read_resp(response):
#     print(response.text)

# def get_password_leaks_ct(hashes, user_hash2):
#    hashes_list = []

#    #TODO: This factory is not working check 'hashx' to make sure split is working properly
#    #TODO:Possibly use a profiler pdb pudb etc...
#    hashes2 = (line.split(':') for line in hashes.text.splitlines())
#    for hashx, count in hashes2:
#        print ('Hashx: ', hashx)
#        if (len(hashx)) == (len(user_hash2)) and hashx == user_hash2:
#            hashes_list.append({'hashed password': hashx, 'times cracked': int(count)})
#            print('This never hits! But youve been hacked')
#        else:
#            #print("hash length missmatch")
#            continue
def get_password_leaks_ct(hashes, user_hash2):
    hashes_list = []

    #TODO: This factory is not working check 'hashx' to make sure split is working properly
    #TODO:Possibly use a profiler pdb pudb etc...
    hashes2 = (line.split(':') for line in hashes.text.splitlines())
    for hashx, count in hashes2:
        # print ('Hashx: ', hashx)
        if (len(hashx)) == (len(user_hash2)) and hashx == user_hash2:
            hashes_list.append({'hashed password': hashx, 'times cracked': int(count)})
            print('This never hits! But youve been hacked')
        else:
            #print("hash length missmatch")
            continue
    #print(hashes_list)

    #hashed_dict_sort(hashes_list)

def hashed_dict_sort(hashes_list):
    #TODO: iterate over list of dict and use this function to sort and return the value
    for item in hashes_list:
        for key, value in item:
            print(key, value)

    # if hashx == user_hash:
    #     print('HIT insecure!!!')
    #     prints_len_and_item(hashx, user_hash)

    # else:
    #     print("Youre good! Move along!")
    #     print(f' Hash-X: {hashx} User  Hash: {user_hash}')
    #     prints_len_and_item(hashx, user_hash)
    #     x += 1
    #     print(count)

def get_passwords_from_txt_file():
    pass

def print_password_and_size(input_pw, times_hacked):
    print(f'User Password is: {input_pw} and its size is:', (len(input_pw)))

def main(args):
    for password in args:
        old_pw = password
        password = hashlib.sha1(password.encode('utf-8')).hexdigest()
        #print('Password 1 and 2', password, old_pw)
        # print(len(password))

        count = pwned_api_check(password)
        if count is None:
            times_hacked = 0

        if times_hacked > 0:
            print(f'Match! Your Password : {old_pw} has been compromised: {times_hacked} times.')
            print('You should change your password!')
            print_password_and_size(old_pw, times_hacked)
            #continue
        else:
            print(f'Youre all good! Party on! Your password: {old_pw} has been hacked {times_hacked} times!')
            continue
        return 'DONE!'

if __name__ == '__main__':
    main(sys.argv[1:])

import hashlib
import struct
import base64
import random
import string
from blowfish import BlowFish
from idea import IDEA_Encryption


username = 'bill'
register_code = ''

def randomString(stringLength=8):
    letters = string.ascii_uppercase
    return ''.join(random.choice(letters) for i in range(stringLength))

def generate_8_upper_case():
    # Family License that covers up to 5 computers 1111
    family_registeration_code = "{0}{1}{2}{3}{4}{5}{6}{7}".format(randomString(1), 'P', randomString(1), 'N', randomString(1), 'K', randomString(1), 'E')
    # Educational Site License 4997
    education_site_registeration_code = "{0}{1}{2}{3}{4}{5}{6}{7}".format(randomString(1), 'V', randomString(1), 'Q', randomString(1), 'R', randomString(1), 'M')
    # Educational Worldwide License 4998
    education_worldwide_registeration_code = "{0}{1}{2}{3}{4}{5}{6}{7}".format(randomString(1), 'W', randomString(1), 'Q', randomString(10), 'R', randomString(1), 'M')
    # Corporate Site License 4999
    Corporate_site_registeration_code = "{0}{1}{2}{3}{4}{5}{6}{7}".format(randomString(1), 'X', randomString(1), 'Q', randomString(1), 'R', randomString(1), 'M')
    # Corporate Worldwide License  5000
    corporate_worldwide_registeration_code = "{0}{1}{2}{3}{4}{5}{6}{7}".format(randomString(1), 'T', randomString(1), 'R', randomString(1), 'K', randomString(1), 'E')
    
    return [family_registeration_code, education_site_registeration_code, education_worldwide_registeration_code, Corporate_site_registeration_code, corporate_worldwide_registeration_code]
    
    

def get_sha_one_value(data, is_hex):
    sha_one = hashlib.sha1(data)
    if is_hex:
        return sha_one.hexdigest()
    else:
        return sha_one.digest()

def get_sha_512_value(data, is_hex):
    sha_512 = hashlib.sha512(data)
    if is_hex:
        return sha_512.hexdigest()
    else:
        return sha_512.digest()

def character_intersect(uname, rcode):
    uname_length = len(uname)
    rcode_length = len(rcode)
    s = ''
    i = j = num = 0
    while i < uname_length and j < rcode_length:
        if num % 2 == 0:
            s += uname[i]
            i += 1
        else:
            s += rcode[j]
            j += 1
        num += 1
    if j != rcode_length:
        s += rcode[j:8]
    if i != uname_length:
        s += uname[i:]
    return s.upper()


def front_8_character():
    s_first = 'me4T6cBLV'
    s_second = register_code[:8]
    s_third = 'CpCwxrvCJZ30pKLu8Svxjhnhut437glCpofVssnFeBh2G0ekUq4VcxFintMix52vL0iJNbdtWqHPyeumkDUC+4AaoSX+xpl56Esonk4='
    sha_one_data = (s_first + s_second + s_third).encode('utf-8')
    
    # sha_one hash
    key_sha_one = get_sha_one_value(sha_one_data, False)
    # print("front_8_character, key_sha_one: {0}".format(get_sha_one_value(sha_one_data, True)))

    # hash for blowfish key
    bf = BlowFish(key_sha_one)
    bf.generate_subkey()

    # sha512 hash
    t_first = register_code[:8]
    t_second = '96338'
    t_third = character_intersect(username, register_code[:8])
    sha_512_data = (t_first + t_second + t_third).encode('utf-8')

    key_sha_512 = get_sha_512_value(sha_512_data, False)
    # print("front_8_character, key_sha_512: {0}".format(get_sha_512_value(sha_512_data, True)))
    
    # hash for IDEA key
    idea = IDEA_Encryption(key_sha_512[0:16])
    idea.generate_subkey()

    # blowfish encrypt
    plain_text = t_third
    first_cipher = str()
    blowfish_encrypt_result = bf.main_transform(0, 0)
    for i in range(len(plain_text)):
        tmp = bf.main_transform(blowfish_encrypt_result[0], blowfish_encrypt_result[1])
        first_cipher += chr(((tmp[0] >> 24) & 0xff) ^ ord(plain_text[i]))
        blowfish_encrypt_result[0] = ((blowfish_encrypt_result[0] << 8) & 0xffffffff) | blowfish_encrypt_result[1] >> 24
        blowfish_encrypt_result[1] = ((blowfish_encrypt_result[1] << 8) & 0xffffff00) | ((tmp[0] >> 24) & 0xff) ^ ord(plain_text[i])

    first_cipher_base64 = base64.b64encode(first_cipher.encode('latin1'))

    # print("the first 8 character, blowfish base64 cipher: "  + str(first_cipher_base64))

    # IDEA encrypt
    plain_text = first_cipher_base64
    two_cipher = str()
    IDEA_zero_byte = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    IDEA_encrypt_result = idea.encrypt(IDEA_zero_byte)

    for i in range(len(plain_text)):
        tmp = idea.encrypt(IDEA_encrypt_result)
        two_cipher += chr(tmp[0] & 0xff ^ plain_text[i])
        IDEA_encrypt_result = IDEA_encrypt_result[1:] + chr(tmp[0] & 0xff ^ plain_text[i]).encode('latin1')
    
    two_cipher_base64 = base64.b64encode(two_cipher.encode('latin1'))
    # print("the first 8 character, IDEA base64 cipher" + str(two_cipher_base64))

    # choose the first 8 upper character
    upper_character = str()
    front_8_rcode = register_code[:8]
    for i in two_cipher_base64:
        if i >= 0x41 and i <= 0x5a:
            upper_character += chr(i)

    return upper_character[:8] if len(upper_character) >= 8 else []

def middle_8_character():
    
    plain_text = b'09232849248398340903834873297239340547237623242043324398489390309284343843223493299435'

    # sha 512 key
    key_sha_512 = get_sha_512_value(plain_text, False)
    # print("middle_8_character, key_sha_512: {0}".format(get_sha_512_value(plain_text, True)))

    # blowfish encryption
    bf = BlowFish(key_sha_512[:56])
    bf.generate_subkey()
    
    # sha-1 key
    s_first = register_code[:8]
    s_second = '96338'
    s_third = character_intersect(username, register_code[:8])
    plain_text = (s_first + s_second + s_third).encode('utf-8')
    key_sha_one = get_sha_one_value(plain_text, False)
    # print("middle_8_character, key_sha_one: {0}".format(get_sha_one_value(plain_text, True)))
    
    # IDEA encryption
    idea = IDEA_Encryption(key_sha_one[:16])
    idea.generate_subkey()

    # IDEA encrypt
    plain_text = (s_third).encode('utf-8')
    plain_length = len(plain_text)
    first_cipher = bytearray(plain_length)
    IDEA_zero_byte = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    IDEA_encrypt_result = idea.encrypt(IDEA_zero_byte)
    times = ord(register_code[0]) - 0x31
    for i in range(plain_length * times):
        tmp = idea.encrypt(IDEA_encrypt_result)
        first_cipher[i % plain_length] = tmp[0] & 0xff ^ plain_text[i % plain_length]
        IDEA_encrypt_result = IDEA_encrypt_result[1:] + chr(tmp[0] & 0xff ^ plain_text[i % plain_length]).encode('latin1')
    
    first_cipher_base64 = base64.b64encode(first_cipher)
    # print("the middle 8 character, IDEA base64 cipher" + str(first_cipher_base64))


    # blowfish encrypt
    plain_text = first_cipher_base64
    two_cipher = bytearray(len(plain_text))
    blowfish_zero_byte = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    blowfish_encrypt_result = bf.main_transform(0, 0)
    for i in range(len(plain_text)):
        tmp = bf.main_transform(blowfish_encrypt_result[0], blowfish_encrypt_result[1])
        two_cipher[i] = (tmp[0] >> 24) & 0xff ^ plain_text[i]
        blowfish_encrypt_result[0] = ((blowfish_encrypt_result[0] << 8) & 0xffffffff) | blowfish_encrypt_result[1] >> 24
        blowfish_encrypt_result[1] = ((blowfish_encrypt_result[1] << 8) & 0xffffff00) | ((tmp[0] >> 24) & 0xff) ^ plain_text[i]

    two_cipher_base64 = base64.b64encode(two_cipher)

    # print("the first 8 character, blowfish base64 cipher: "  + str(two_cipher_base64))    


    upper_character = str()
    back_4_rcode = register_code[-4:]
    for i in two_cipher_base64:
        if i >= 0x41 and i <= 0x5a:
            upper_character += chr(i)

    return upper_character[:4] if len(upper_character) >= 4 else []

def check(data):
    first = str(ord(data[4-1]) - ord('M')) # 3
    second = str(ord(data[8-1]) - ord('D')) # 7
    third = str(ord(data[6-1]) - ord('I')) # 5
    forth = str(ord(data[2-1]) - ord('O')) # 1
    s = first + second + third + forth
    if '-' in s:
        return False

    return True

def main():
    global username
    global register_code
    username = input('please input a username: ')
    username = username.upper()
    registeration_code = generate_8_upper_case()
    hint_information = [
        "Family License",
        "Educational Site License",
        "Educational Worldwide License",
        "Corporate Site License",
        "Corporate Worldwide License"
    ]
    for i in range(len(registeration_code)):
        register_code = registeration_code[i]
        first = front_8_character() # front 8 character
        second  = middle_8_character()
        if len(first) > 0 and len(second) > 0:
            full_register_code = register_code + first + second
            result = check(full_register_code)
            if result:
                print("{0}: {1}".format(hint_information[i], full_register_code))



if __name__ == "__main__":

    main()
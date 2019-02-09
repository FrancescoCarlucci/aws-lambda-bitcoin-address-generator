import json
import ecdsa
import hashlib
import random

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# takes 26 byte input, returns string
def processAddr(payload):
    assert(len(payload) >= 26)
    return '%d.%d.%d.%d:%d' % (ord(payload[20]), ord(payload[21]),
                               ord(payload[22]), ord(payload[23]),
                               struct.unpack('!H', payload[24:26])[0])

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def base58decode(s):
    result = 0
    for i in range(0, len(s)):
        result = result * 58 + b58.index(s[i])
    return result

def base256encode(n):
    result = ''
    while n > 0:
        result = chr(n % 256) + result
        n /= 256
    return result

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result

def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, '\0')
    return '1' * leadingZeros + base58encode(base256decode(result))

def base58CheckDecode(s):
    leadingOnes = countLeadingChars(s, '1')
    s = base256encode(base58decode(s))
    result = '\0' * leadingOnes + s[:-4]
    chk = s[-4:]
    checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
    assert(chk == checksum)
    version = result[0]
    return result[1:]

# https://en.bitcoin.it/wiki/Wallet_import_format
def privateKeyToWif(key_hex):
    return base58CheckEncode(0x80, key_hex.decode('hex'))

def wifToPrivateKey(s):
    b = base58CheckDecode(s)
    return b.encode('hex')

# Input is a hex-encoded, DER-encoded signature
# Output is a 64-byte hex-encoded signature
def derSigToHexSig(s):
    s, junk = ecdsa.der.remove_sequence(s.decode('hex'))
    if junk != '':
        print 'JUNK', junk.encode('hex')
    assert(junk == '')
    x, s = ecdsa.der.remove_integer(s)
    y, s = ecdsa.der.remove_integer(s)
    return '%064x%064x' % (x, y)

# Input is hex string
def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

# Input is hex string
def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return base58CheckEncode(0, ripemd160.digest())

def addrHashToScriptPubKey(b58str):
    assert(len(b58str) == 34)
    # 76     A9      14 (20 bytes)                                 88             AC
    return '76a914' + base58CheckDecode(b58str).encode('hex') + '88ac'

def lambda_handler(event, context):
    
    private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
    wif = privateKeyToWif(private_key)
    address = keyToAddr(private_key)
    
    answer = {'private_key':private_key,'private_wif':wif,'public_address':address}
    
    return {
        "statusCode": 200,
        "body": json.dumps(answer, separators=(',', ':') )
    }

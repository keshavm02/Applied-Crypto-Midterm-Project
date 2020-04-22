import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64

# RSA to use
key = RSA.generate(4096, e=65537)

# generate private key
priv_key = key.exportKey("PEM")

# generate public key
pub_key = key.publickey().exportKey("PEM")


# store ciphertexts received in this array to blacklist any ciphertext that is repeated
ciphertexts_received = []



# iMessage encrypts the AES 256 bit key with message recipient's public RSA key
def encryptKeyUsingRSA(AES_key, public_key):
    rsa_key = PKCS1_OAEP.new(RSA.import_key(public_key))
    ret = rsa_key.encrypt(AES_key)
    return base64.b64encode(ret)

# randomly generated 256 bit AES key
AESKey = b"4tXylwKtjemGH7TGbcoDAwjUv0N9A8Wzf+GmLzg0OEs="

# generate ciphertext through RSA encryption of AES key with the public key of recipient
ciphertext = encryptKeyUsingRSA(AESKey, pub_key)
print('CIPHERTEXT OF ENCRYPTED AES KEY:\n\n', ciphertext, '\n\n\n\n')

# function to decrypt ciphertext containing AES key
def decryptKeyUsingRSA(ciphertext, private_key):
    if ciphertext in ciphertexts_received:
        # fail silently if ciphertext has already been received before, so that 
        # we don't act as an oracle
        return

    # add new ciphertext to list of received ciphertexts so we can blacklist 
    # this if we receive it again
    ciphertexts_received.append(ciphertext)

    # generate rsa key from private key to decrypt ciphertext
    rsa_key = PKCS1_OAEP.new(RSA.importKey(private_key))

    # decode base64 encoding
    encrypted = base64.b64decode(ciphertext)
    
    # set return value as the decrypted key to use so the recipient of the message 
    # can decrypt the actual message with this AES key
    ret = rsa_key.decrypt(encrypted)

    return ret

# decrypt ciphertext to generate AES key
original = decryptKeyUsingRSA(ciphertext, priv_key)

# should be same as the original AES key we encrypted
print('ORIGINAL UNENCRYPTED AES KEY:\n\n', original)


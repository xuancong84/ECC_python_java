from tinyec import registry, ec
from Crypto.Cipher import AES
from Crypto.Util.Padding import *
import hashlib, secrets


def encrypt_AES_CBC(msg, AESKey):
    aesCipher = AES.new(AESKey, AES.MODE_CBC)
    ciphertext = aesCipher.encrypt(pad(msg, AES.block_size))
    return (ciphertext, aesCipher.iv)

def decrypt_AES_CBC(ciphertext, AESKey, iv):
    aesCipher = AES.new(AESKey, AES.MODE_CBC, iv)
    plaintext = aesCipher.decrypt(ciphertext)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('secp256r1')

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    AESPoint = ciphertextPrivKey * pubKey
    AESKey = ecc_point_to_256_bit_key(AESPoint)
    ciphertext, iv = encrypt_AES_CBC(msg, AESKey)
    EncryptedAESKey = ciphertextPrivKey * curve.g
    return (ciphertext, iv, EncryptedAESKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, iv, EncryptedAESKey) = encryptedMsg
    AESPoint = privKey * EncryptedAESKey
    AESKey = ecc_point_to_256_bit_key(AESPoint)
    plaintext = unpad(decrypt_AES_CBC(ciphertext, AESKey, iv), AES.block_size)
    return plaintext


# MAIN starts here
if __name__ == '__main__':
    # Python encode Python decode
    msg = b'Text to be encrypted by ECC public key and decrypted by its corresponding ECC private key1234567'
    print("original msg:", msg)
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g

    print('Private key:', privKey)
    print('Public key:', pubKey)

    encryptedMsg = encrypt_ECC(msg, pubKey)
    encryptedMsgObj = {
        'ciphertext': encryptedMsg[0].hex(),
        'IV': encryptedMsg[1].hex(),
        'EncryptedAESKey': '(%d, %d)'%(encryptedMsg[-1].x, encryptedMsg[-1].y)
    }
    print("encrypted msg:", encryptedMsgObj)

    decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
    print("decrypted msg:", decryptedMsg)

    # Java encode Python decode
    decryptedMsg2 = decrypt_ECC([bytearray.fromhex('683e9cea584a9408821735c958a8a95e94f37c0fe3373e165a414f5cece7fb593ccd9ad18c0b90622f5001b636ee287aed2fc7e127906afcbb7df68f054e4daf6a773aeafb6471a92ee2ef4bb01148ed06b8c7a8cf48972bfe0247c6852efc8f2b0dbf62c978961372873574232b00b2'),
                         bytearray.fromhex('7de7c7a397e3ac1266f02baa9b3d4cbe'),
                         ec.Point(curve,
                                  106504475433703131298556354423268993749403842826244952418115160744777692256733,
                                  112353531522751447419464862576385479114567958719827052736911763021690231831294)],
                        75186921650391519650532175449590053817943957292013655745118533638504557674992)
    print("Java-encrypted decrypted msg:", decryptedMsg2)

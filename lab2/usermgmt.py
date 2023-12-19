import sys
import os
import getpass
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

if len(sys.argv) != 3:
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

	if sys.argv[1] == 'add':
		if sys.argv[2] in mgmtDict.keys():
			print("User aldready added.")
		else:
			
			#password = input("Password: ")
			password = getpass.getpass(prompt='Password: ')
			while len(password) < 8:
				print("Password has to be at least 8 characters long.")
				password = getpass.getpass(prompt='Password: ')
			#pass2 = input("Repeat password: ")
			pass2 = getpass.getpass(prompt='Repeat password: ')
			if password != pass2:
				print("User add failed. Password mismatch.")
			else:
				f = open("mgmt.txt", "w")
				salt = get_random_bytes(16) 
				v = scrypt(password.encode(), salt, 16, N=2**14, r=8, p=1)
				val = v + salt + b'0'
				mgmtDict[sys.argv[2]] = val.hex()
				for key, value in mgmtDict.items():
					f.write(key + " " + value + "\n")
				print("User " + sys.argv[2] + " successfuly added.")
				f.close()

	elif sys.argv[1] == 'passwd':
		if sys.argv[2] not in mgmtDict.keys():
			print("Uknown user.")
		else:
			password = getpass.getpass(prompt='Password: ')
			while len(password) < 8:
				print("Password has to be at least 8 characters long.")
				password = getpass.getpass(prompt='Password: ')
			pass2 = getpass.getpass(prompt='Repeat password: ')
			if password != pass2:
				print("Password change failed. Password mismatch.")
			else:
				f = open("mgmt.txt", "w")
				valueDataHex = mgmtDict[sys.argv[2]]
				valueDataByte = bytes.fromhex(valueDataHex)
				forcepass = valueDataByte[-1:]
				
				salt = get_random_bytes(16) 
				v = scrypt(password.encode(), salt, 16, N=2**14, r=8, p=1)
				val = v + salt + forcepass
				mgmtDict[sys.argv[2]] = val.hex()
				for key, value in mgmtDict.items():
					f.write(key + " " + value + "\n")
				print("Password change successful.")
				f.close()

	elif sys.argv[1] == 'forcepass':
		if sys.argv[2] not in mgmtDict.keys():
			print("Uknown user.")
		else:
			f = open("mgmt.txt", "w")
			val = mgmtDict[sys.argv[2]]
			valBytes = bytes.fromhex(val)
			valData = valBytes[:-1]
			valBytes = valData + b'1'
			mgmtDict[sys.argv[2]] = valBytes.hex()
			for key, value in mgmtDict.items():
				f.write(key + " " + value + "\n")
			f.close()
			print("User will be requested to change password on next login.")
	elif sys.argv[1] == 'del':
		if sys.argv[2] not in mgmtDict.keys():
			print("Uknown user.")
		else:
			f = open("mgmt.txt", "w")
			del mgmtDict[sys.argv[2]]
			for key, value in mgmtDict.items():
				f.write(key + " " + value + "\n")
			f.close()
			print("User successfuly removed.")
        

    



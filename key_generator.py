from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import os

"""
@generate_key
This function will generate the public and private keys.

Public key is shared among users and it is used to encrypt data.
It is users/bot owners responsability to make sure that only he/she has access to private key.
Data can only be decrypted with private key.

out : public  keys in pastebot.net
out : private keys in privatekey.net (keep these secure)

Any number of key pairs can be generated.
"""
def generate_key():
	random_generator = Random.new().read
	key = RSA.generate(1024, random_generator)
	print("Key successfully generated.")
	name = input("Enter the file name to store the keys : ")
	print("WARNING : Do not share your private key with anyone.")
	print("Public key stored in file  : ",name,"public.pem",sep="")	
	print("Private key stored in file : ",name,"private.pem",sep="")
	with open(os.path.join("privatekey.net",name+"private.pem"), 'wb') as fo:
		fo.write(key.exportKey())
	public_key = key.publickey()
	with open(os.path.join("pastebot.net",name+"public.pem"), 'wb') as fo:
		fo.write(public_key.exportKey())	
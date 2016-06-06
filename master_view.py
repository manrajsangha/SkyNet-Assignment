import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import pickle

"""
@decrypt_valuables
The data can only be decrypted by using private key,
which must be only accessible to the bot owner.
in : encrypted data
in : private key, which will be used for decryption
out : decrypted data
"""
def decrypt_valuables(f):
	priv_key = input("private key file name : ")	
	if not os.path.exists(os.path.join("privatekey.net", priv_key)):
		print("private key file not found")
		os.exit(1)
	with open(os.path.join("privatekey.net", priv_key), 'rb') as fo:
		private_key = fo.read()
	data = pickle.load(f)
	pycrypto_key =  RSA.importKey(private_key)	
	return pycrypto_key.decrypt(data).decode('utf-8')


if __name__ == "__main__":
	try:
		fn = input("Which file in pastebot.net does the botnet master want to view? ")
		if not os.path.exists(os.path.join("pastebot.net", fn)):
			print("The given file doesn't exist on pastebot.net")
			os.exit(1)
		f = open(os.path.join("pastebot.net", fn), "rb")#.read()
		print (decrypt_valuables(f))
	except:
		print ("You provided some wrong inputs. Try again")
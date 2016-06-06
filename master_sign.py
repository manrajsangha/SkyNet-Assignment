import os
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import pickle
from Crypto.Signature import PKCS1_v1_5

"""
@sign_file
We use your private key to write message's signature, and 
revceiver uses the public key to check if it's really our message.
in  : plain file, non encrypted.
out : digital signature in new file named as originalfile.signed 
"""
def sign_file(f):
	# TODO: For Part 2, you'll use public key crypto here
	# The existing scheme just ensures the updates start with the line 'Caesar'
	# This is naive -- replace it with something better!
	priv_key = input("private key file name : ")
	if not os.path.exists(os.path.join("privatekey.net", priv_key)):
		print("private key file not found")
		os.exit(1)
	with open(os.path.join("privatekey.net", priv_key), 'rb') as fo:
		private_key = fo.read()
	pycrypto_key =  RSA.importKey(private_key)
	
	hash = SHA256.new(f)
	signer = PKCS1_v1_5.new(pycrypto_key)		
	return signer.sign(hash)


if __name__ == "__main__":
	try:
		fn = input("Which file in pastebot.net should be signed? ")
		if not os.path.exists(os.path.join("pastebot.net", fn)):
			print("The given file doesn't exist on pastebot.net")
			os.exit(1)
		f = open(os.path.join("pastebot.net", fn), "rb").read()
		signed_f = sign_file(f)
		signed_fn = os.path.join("pastebot.net", fn + ".signed")
		out = open(signed_fn, "wb")
		out.write(pickle.dumps(signed_f, protocol=pickle.HIGHEST_PROTOCOL))
		out.close()
		print("Signed file written to", signed_fn)
	except:
		print ("You provided some wrong inputs. Try again")
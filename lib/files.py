import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random #Importing PRNG
from Crypto.Hash import SHA256 #Authentication Hash
from Crypto.Signature import PKCS1_v1_5 #Used for authentication of signature 
from key_generator import generate_key
import pickle

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

###

def save_valuable(data):
    valuables.append(data)

"""
@encrypt_for_master
This function encrypts the data/valuables before uploading to pastebot.net

in  : Public key to be used for encryption
out : Encrypted data
"""	
def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master
	pub_key = input("public key file name : ")
	print (pub_key)
	if not os.path.exists(os.path.join("pastebot.net", pub_key)):
		print("Public key file not found")
		os.exit(1)
	with open(os.path.join("pastebot.net", pub_key), 'rb') as fo:
		public_key = fo.read()
	pycrypto_key =  RSA.importKey(public_key)
	return pycrypto_key.encrypt(data.encode('utf-8'), 32)

def upload_valuables_to_pastebot(fn):
	# Encrypt the valuables so only the bot master can read them
	print("If you have not generated the keys yet than please do it using command : newkey")
	ans = input("Do you want to generate keys (yes/no)? : ")
	if ans.lower() == "yes":
		generate_key()
	valuable_data = "\n".join(valuables)
	#valuable_data = bytes(valuable_data, "ascii")
	encrypted_master = encrypt_for_master(valuable_data)

	# "Upload" it to pastebot (i.e. save in pastebot folder)
	f = open(os.path.join("pastebot.net", fn), "wb")
	f.write(pickle.dumps(encrypted_master, protocol=pickle.HIGHEST_PROTOCOL))	
	f.close()

	print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

"""
@verify_file
This function verifys the original data and the encrypted data using the signature.
Before calling this funtion, user must sign the uploaded file.
users cannot download the file if bot owner has not signed the file.
"""
def verify_file(fn,f):
	#def verify_file(f):
	# Verify the file was sent by the bot master
	# TODO: For Part 2, you'll use public key crypto here
	# Naive verification by ensuring the first line has the "passkey"
	if not os.path.exists(os.path.join("pastebot.net", fn+".signed")):
		print("The given file doesn't exist on pastebot.net")
		return	
	pub_key = input("Public key file name : ")
	if not os.path.exists(os.path.join("pastebot.net", pub_key)):
		print("public key file not found")
		os.exit(1)
	with open(os.path.join("pastebot.net", pub_key), 'rb') as fo:
		public_key = fo.read()		
	pycrypto_key =  RSA.importKey(public_key)
	verifier = PKCS1_v1_5.new(pycrypto_key)
	
	print("Checking signature in ",fn+".signed","file")		
	hash = SHA256.new(f)#.digest()	
	fh = open(os.path.join("pastebot.net", fn+".signed"), "rb")		
	signature = pickle.load(fh)
	return verifier.verify(hash, signature)
	

def process_file(fn, f):
    if verify_file(fn,f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    #data = pickle.load(f)
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn)
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass

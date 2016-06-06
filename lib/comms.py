import struct
import datetime
import Random

#from Crypto.Cipher import XOR
from Crypto.Hash import HMAC
from Crypto.Cipher import AES


from dh import create_dh_key, calculate_dh_secret

timestamp_len = 26 #Specifiying length of the string

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_hash = None 
        self.last_time = datetime.datetime.now()
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            if self.verbose:
                print("Shared hash: {}".format(self.shared_hash))
            self.shared_hash = bytes.fromhex(self.shared_hash)

        #AES in CBC Mode For Encryption
        random_seed = (random.seed * self_shared)
        iv = random.getrandbits(16) #Random Initialization vector
        self.cipher = AES.new(self.shared_hash, AES.MODE_CBC, iv) #Creates The Cipher Object

    def send (self, msg):
        #Initialising string with "b" to indicate byte string. 
        if type(msg) !=type(b""):
            #bytes converter. 
                msg = bytes(msg,'ascii')
            #True or False 
        if self.verbose:
            print("Function 'Send' Recieved msg", msg,type(msg))
            
        #Creating a HMAC and additing it to the message.
        if self.shared_hash !=None:
            hmac= HMAC.new(self.shared_hash, msg = encrypted_data)
            hmac.update(msg) #Added the message by updating Hash
        #Compare Hexdigest of each hash
        if self.verbose:
                print("Hex Digest Is:", hmac.hexdigest())
            mac = bytes(hmac.hexdigest() + msg.decode("ascii"), "acii")
        else:
            mac = msg
        if self.verbose:
            print("Msg is now encoded", mac, type(mac))
        
        #Timestamp
        #Importing timestamp into the message
        current_time = str (datetime.datetime.now()) #Formatted to string
        mac = bytes(current_time,'ascii') + mac #Added to message
        
        def send(self, data):
        if self.cipher:
            encrypted_data = self.cipher.encrypt(mac) #Encrypt the message
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = mac
            if self.verbose
                print("Encrypted data is same as data",type(encrypted_data))
                

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    #Removing Timestamp
    
    stamp = str(data,[:timestamp_len],'ascii') #_len Returns the lenght of the string storing into data
    data = data [timestamp_len:]

    #Getting the HMAC & Verifying
    if self.shared_hash != None:
        hmac = HMAC.new(self.shared_hash)
        hmac_msg = data [:hmac.digest_size*2] #HMAC OF THE MESSAGE
        data = data [hmac.digest+size*2]#MSG part of the message
        hmac.update(data)
        if h.hexidigest() !=str(hmac, 'ascii'):
            if self.verbose:
                print("bad message")
                print ("hmac from message is: ", str(hmac_msg, 'ascii'))
                print ("hmac from digest:", hmac.hexdigest())
                print ("no verfiication of message", data)
            raise RuntimeError ("bad message: HMAC does not match")
    
    #Check Timestamp to see if it is valid
    msg_time = str (datetime.datetime.now())
    if self.verbose:
        print(msg_time)
    if msg_time <= self.last_time #If the timestamp is not newer than the current time it will raise the following error.
    if self.verbose:
        print("Breach in Timestamp")
        print("timestamp is: ", stamp)
    raise RuntimeError("Timestamp is not newer than the last one recived")
    self.last_message_time = msg_time #Updates the message time.

    return data
    
    def close(self):
        self.conn.close()

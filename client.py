from socket import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from threading import Thread
import threading
import os
import signal
import sys
import atexit



private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

def encrypt(string,key):
    Enc = key.encrypt(string.encode("utf-8"),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    return Enc

def decrypt(data,key):
    return key.decrypt(
    data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    ).decode("utf-8")

def encryptBytes(B,key):
    Enc = key.encrypt(B,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    return Enc

def decryptToBytes(data,key):
    return key.decrypt(
    data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    )

doRun = True

serverKey = ""

host = "" # set to IP address of target computer
port = 42069
addr = (host,port)
connected = False
name = ""
UDPSock = socket(AF_INET, SOCK_DGRAM)

class KeyboardThread(threading.Thread):

    def __init__(self, input_cbk = None, name='keyboard-input-thread'):
        self.input_cbk = input_cbk
        super(KeyboardThread, self).__init__(name=name)
        self.start()

    def run(self):
        while doRun:
            self.input_cbk(input())

def my_callback(data):
    global host
    global port
    global addr
    global doRun
    global name

    cmd = data.split(" ")[0]
    args = data.split(" ")

    isFile = False

    #print(args[1].split(":"))

    if cmd == "exit":
        doRun = False

    if data.startswith("\"") and data.endswith("\""):
        if os.path.isfile(data.replace("\"","")):
            isFile = True
            data = data.replace("\"","")

    if host == "":
        if cmd == "connect" and len(args) > 1:
            host = args[1].split(":")[0]
            port = int(args[1].split(":")[1])
            addr = (host,port)
            name = args[2]
            UDPSock.sendto(("init").encode("utf-8"),addr)
            UDPSock.sendto(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo),addr)
            print("Connecting to",host)
            print("If you do not receive an answer type 'cancel' to try again")
    elif serverKey == "" and cmd == "cancel":
        host = ""
        print("Stopped trying to connect.")
    elif not serverKey == "" :
        if not isFile:
            if cmd == "getfile":
                UDPSock.sendto(encrypt(data,serverKey),addr)
            else:
                UDPSock.sendto(encrypt(name + ": " + data,serverKey),addr)
        else:
            filename,fileext = os.path.splitext(data)
            print(fileext)
            UDPSock.sendto(((open(data,"rb").read()) + fileext.encode("utf-8") + "file".encode("utf-8")),addr)
    else:
        print(serverKey)

#start the Keyboard thread
kthread = KeyboardThread(my_callback)

host2 = "0.0.0.0" # set to IP address of target computer
port2 = 69
addr2 = (host2,port2)
ListenSock = socket(AF_INET, SOCK_DGRAM)
ListenSock.bind(addr2)

NextCallIsServerkey = False

print("Begin by using the command 'connect'")
print("Example: connect SERVERIP:PORT YOURNAME")

def onExit():
    if not serverKey == "":
        UDPSock.sendto(encrypt("leave",serverKey),addr)
    UDPSock.close()
    ListenSock.close()

atexit.register(onExit)

while doRun:
    global serverkey
    (dat,adr) = ListenSock.recvfrom(1024)

    if NextCallIsServerkey:
        serverKey = serialization.load_pem_public_key(dat,default_backend())
        NextCallIsServerkey = False
        print("Received server key")
    else:
        try:
            if dat.decode("utf-8") == "key":
                NextCallIsServerkey = True
        except:
            dataa = decrypt(dat,private_key)
            if not dataa.startswith(name):
                print("")
                print(decrypt(dat,private_key))

onExit()

os._exit(0)
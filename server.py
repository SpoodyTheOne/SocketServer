from socket import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import time

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

def socketSendData(data,socket):
    Enc = encrypt(data,Keys[socket])
    Sender.sendto(Enc,(socket,69))

def sendAll(msg):
    for k,v in Sockets.items():
        socketSendData(msg,k)

buf = 1048576
host = "0.0.0.0" # set to IP address of target computer
port = 4242
addr = (host,port)
UDPSock = socket(AF_INET, SOCK_DGRAM)
UDPSock.bind(addr)

host2 = "" # set to IP address of target computer
port2 = 1412
Sender = socket(AF_INET, SOCK_DGRAM)

#print(addr[1])

Sockets = {}
Keys = {}
Ports = {}

def addSocket(raddr):
    global Sockets
    global Ports

    Sockets[raddr[0]] = raddr[0]
    Ports[raddr[0]] = raddr[1]
    #print("New Connection!",raddr[0])

while True:
    (data, raddr) = UDPSock.recvfrom(buf)
    if not raddr[0] in Sockets:
        try:
            if (data.decode("utf-8").startswith("init")):
                addSocket(raddr)
        except:
            print("Error while trying to decode init signal sent by new user")
    elif not raddr[0] in Keys:
        Keys[raddr[0]] = serialization.load_pem_public_key(data,default_backend())
        Sender.sendto("key".encode("utf-8"),(raddr[0],69))
        Sender.sendto(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo),(raddr[0],69))
        print("Received key of socket",raddr[0])
        for k,v in Sockets.items():
            socketSendData("New connection",k)
    else:
        try:
            data = decrypt(data,private_key)
            print("(" + raddr[0] + ") " + data)

            if data == "leave":
                del Sockets[raddr[0]]
                del Keys[raddr[0]]
                del Ports[raddr[0]]
            else:
                sendAll(data)
        except:
            if True:
                dataBytes = data
                fileType = ""
                dataLen = len(dataBytes)-1
                i = dataLen
                while i > 1 and not chr(dataBytes[i]) == '.':
                    fileType = fileType + chr(dataBytes[i])
                    i = i-1

                fileType = fileType.replace("elif",".")

                if dataBytes.endswith("file".encode("utf-8")):
                    na = str(int(time.time())) + fileType
                    open("/temp/" + na,"wb+").write(dataBytes)
                    sendAll("getfile " + na)

            else:
                del Sockets[raddr[0]]
                del Keys[raddr[0]]
                del Ports[raddr[0]]

UDPSock.close()
os._exit(0)
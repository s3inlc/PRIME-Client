import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
import socket
import base64
import random
import hashlib

def generateKey():
	random_generator = Random.new().read
	key = RSA.generate(1024, random_generator)
	f = open("key.txt", "w")
	f.write(key.exportKey())
	f.close()
	publickey = key.publickey()
	f = open("publickey.txt", "w")
	f.write(key.publickey().exportKey())
	f.close()


def loadKey():
	f = open("key.txt", "r")
	key = RSA.importKey(f.read())
	f.close()
	f = open("publickey.txt", "r")
	publicKey = RSA.importKey(f.read())
	f.close()
	return (key, publicKey)


def calculateID():
	f = open("publickey.txt", "rb")
	sha1 = hashlib.sha1()
	try:
		sha1.update(f.read())
	finally:
		f.close()
	return sha1.hexdigest()


def cryptTest():
	keys = loadKey()
	privateKey = keys[0]
	publicKey = keys[1]
	
	encrypt = publicKey.encrypt('encrypt this message'.encode('utf-8'), 32)
	print('encrypted message: ', encrypt, '\n')

	decrypt = privateKey.decrypt(ast.literal_eval(str(encrypt)))
	print('decrypted: ', decrypt)


def sendMessage(server):
	keys = loadKey()
	publicKey = keys[1]

	#add Message to String Conversation, Problem with Python 2.x
	message = input("Enter the message:\n")
	encryptedMessage = publicKey.encrypt(message.encode('utf-8'), 32)
	base = base64.b64encode(str(encryptedMessage))
	#print(base)
	idSha = calculateID()
	print(idSha)
	server.send('NEMSG:' + idSha + ':' + base)
	resp = server.recv(1024)
	if resp == 'NEMSG:OK\n':
		print('Sending message succesfull.')
	else:
		print('Something went wrong. Try again later.')


def getMessage(master):
	keys = loadKey()
	privateKey = keys[0]

	master.send('GTSRV')
	serverList = master.recv(1024)
	serverList = serverList[7:-2]
	serverList = serverList.split(';')
	
	slave1 = random.choice(serverList)
	del serverList[serverList.index(slave1)]
	slave2 = random.choice(serverList)

	server1 = serverConnection(slave1.split(',')[0], int(slave1.split(',')[1]))
	server2 = serverConnection(slave2.split(',')[0], int(slave2.split(',')[1]))
	
	idSha = calculateID()
	server1.send('GTMSG:{' + idSha + '}')
	message = server1.recv(100000)
	#print(message)
	message = message[9:] + '='
	#print(message)
	message = base64.b64decode(message)
	#print(message)
	messages = message.split(',)')
	#print(messages)
	i = 1
	for m in messages:
		if (m != ''):
			m = m + ',)'		
			decryptedMessage = privateKey.decrypt(ast.literal_eval(m))
			print(str(i) + ': ' + decryptedMessage)
			i = i+1
	server1.close()
	server2.close()


def serverConnection(ip, port):
	s = socket.socket()
	#host = socket.gethostname()
	host = ip #IP of Server
	port = port #Port of Server

	s.connect((host, port))
	return s


def start():
	s = serverConnection('127.0.0.1', 6667) #Masterserver

	while True:
		var = input("Enter Command ... \n")
		#add help
		if var == 1:
			sendMessage(s)
		elif var == 2:
			getMessage(s)
		elif var == 3:
			loadKey()
		elif var == 4:
			generateKey()
		elif var == 9:
			cryptTest()
		elif var == 0:
			s.close() #Connection to Masterserver closed
			break
		else:
			print('Unknown command. Press ?? for help.')


start()

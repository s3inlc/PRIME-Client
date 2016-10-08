import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
import socket
import base64
import random
import hashlib
from operator import sub
import os.path

def generateKey():
	random_generator = Random.new().read
	key = RSA.generate(1024, random_generator)
	f = open("key.txt", "w")
	f.write(key.exportKey().decode('utf-8'))
	f.close()
	publickey = key.publickey()
	f = open("publickey.txt", "w")
	f.write(key.publickey().exportKey().decode('utf-8'))
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


def writeCacheMessage(idSha, msg):
	#shaID = calculateID()
	#print(shaID)
	if (os.path.isfile('./msg/' + idSha + '/msg.txt')):
		f = open('./msg/' + idSha + '/msg.txt', "a")
		f.write(msg + '\n')
		f.close()
	elif (not os.path.exists('./msg')):
		os.makedirs('./msg')
		os.makedirs('./msg/' + idSha)
		f = open('./msg/' + idSha + '/msg.txt', "w")
		f.write(msg + '\n')
		f.close()
	elif (not os.path.exists('./msg/' + idSha)):
		os.makedirs('./msg/' + idSha)
		f = open('./msg/' + idSha + '/msg.txt', "w")
		f.write(msg + '\n')
		f.close()
	else:
		f = open('./msg/' + idSha + '/msg.txt', "w")
		f.write(msg + '\n')
		f.close()


def readCacheMessage():
	shaID = calculateID()
	if (os.path.isfile('./msg/' + shaID + '/msg.txt')):
		f = open ('./msg/' + shaID + '/msg.txt', "r")
		print(f.read())
		f.close()
	

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

	message = str(input("Enter the message:\n"))
	#print(message)
	encryptedMessage = publicKey.encrypt(message.encode('utf-8'), 32)

	send = encryptedMessage[0]
	#print(encryptedMessage[0])
	send += b'###'
	#print(send + b'\n')
	
	base = base64.b64encode(send)
	#print(base + b'\n')

	idSha = calculateID()
	#print(idSha)

	command = bytes('NEMSG:' + idSha + ':', 'utf8')
	command += base
	#print(command)

	server.send(command)
	resp = server.recv(1024)
	#print(resp)

	if resp == b'NEMSG:OK\n':
		print('Sending message succesfull.')
	else:
		print('Something went wrong. Try again later.')


def getMessage(master):
	keys = loadKey()
	privateKey = keys[0]
	publicKey = keys[1]

	master.send(bytes('GTSRV', 'utf8'))
	serverList = master.recv(1024)
	#print(serverList)
	serverList = serverList[7:-2]
	#print(serverList)
	serverList = serverList.split(b';')
	#print(serverList)
	
	slave1 = random.choice(serverList)
	#print(slave1)
	del serverList[serverList.index(slave1)]
	slave2 = random.choice(serverList)
	#print(serverList)
	#print(slave2)

	server1 = serverConnection(slave1.split(b',')[0], int(slave1.split(b',')[1]))
	server2 = serverConnection(slave2.split(b',')[0], int(slave2.split(b',')[1]))
	
	idSha = calculateID()

	master.send(bytes('GTADD', 'utf-8'))
	listAvailableIDs = master.recv(100000)
	listAvailableIDs = listAvailableIDs[7:-2]
	#print(listAvailableIDs)

	arrayAvailableIDs = listAvailableIDs.split(b';')
	#print(arrayAvailableIDs)

	#randomIDs = bytes('', "utf-8")
	randomIDs = b''
	x = 0
	length = 0

	if (bytes(idSha, 'utf-8') not in arrayAvailableIDs):
		print('Sorry, there are no messages for you available.')
	else:
		indexID = arrayAvailableIDs.index(bytes(idSha, 'utf-8'))
		#print(indexID)
		
		bitVector1 = ""
		bitVector2 = ""
		#print(bitVector1)
		#print(bitVector2)

		#print(len(arrayAvailableIDs))
		#print(length)
		
		while (length < int(len(arrayAvailableIDs))):
			if (length == indexID):
				#print("here")
				bitVector1 += "1"
				bitVector2 += "0"
			else:
				bit = random.randint(0, 1)
				#print(type(bit))
				bitVector1 += str(bit)
				bitVector2 += str(bit)
			length += 1

		#print(bitVector1)
		#print(bitVector2)


		del arrayAvailableIDs[arrayAvailableIDs.index(bytes(idSha, 'utf-8'))]
		
		count = int(len(arrayAvailableIDs)/2)
		#print(count)

		if (count == 0):
			print('There is no privacy available.')
			var = str(input("Do you want to continue with no privacy?[y|n]\n"))
			if var == 'y' or var == 'Y':
				server1.send(bytes('GTMSG:{' + idSha + '}', 'utf8'))
				message1 = server1.recv(100000000)
				message1 = message1[9:-1]
				message1 = base64.b64decode(message1)
				messages1 = message1.split(b'###')

				i = 1

				for m in messages1:
					if (m != '' and m != b''):
						#print(str(m)+'\n')
						decryptedMessage = privateKey.decrypt(m)
						decryptedMessage = decryptedMessage.decode('utf-8')
						writeCacheMessage(idSha, str(decryptedMessage))
						print(str(i) + ': ' + str(decryptedMessage))
						i = i+1
			elif var == 'n' or var == 'N':
				print('Operation canceled.')
			else:
				print('Unknown command. Operation canceled.')
				

		else:
	
			#print(randomIDs)
	
			while (x < count):
				randomID = random.choice(arrayAvailableIDs)
				randomIDs += randomID
				randomIDs += b';'
				del arrayAvailableIDs[arrayAvailableIDs.index(randomID)]
				x += 1
	
			randomIDs = randomIDs[:-1]
			#print(randomIDs.decode('utf-8'))


			#server1.send(bytes('GTMSG:{' + randomIDs.decode('utf-8') + ';' + idSha + '}', 'utf8'))
			server1.send(bytes('GTMSG:{' + bitVector1 + '}', 'utf8'))
			#server2.send(bytes('GTMSG:{' + randomIDs.decode('utf-8') + '}', 'utf8'))
			server2.send(bytes('GTMSG:{' + bitVector2 + '}', 'utf8'))
			message1 = server1.recv(1000000000)
			message2 = server2.recv(1000000000)
			#print(message1)
			#print(message2)
			message1 = message1[9:-1]# + bytes('=', 'utf8')
			message2 = message2[9:-1]# + bytes('=', 'utf8')
			#print(message1)
			#print(message2)
	
			message1 = base64.b64decode(message1)
			message2 = base64.b64decode(message2)
			#print(message1)
			#print(message2)

			list1 = list(bytearray(message1))
			list2 = list(bytearray(message2))

			#print (list1)
			#print (list2)
	
			#print(len(list1))

			#res = map(sub, list1, list2)
			list2 += [0] * (len(list1) - len(list2))
			#print(len(list2))
			res = [a - b for a, b in zip(list1, list2)]
			i = 0
			for elem in res:
				if elem < 0:
					res[i] += 256
				i += 1
			#print(res)

			res = bytes(res)
			#print(res)
		
	
			messages1 = res.split(b'###')
			#print(messages1[0])
			#print(messages1[1])
			#print(messages1[-1])

			if messages1[-1].startswith(b'\x00'):
				del messages1[-1]
	
			#print(messages1)
			i = 1
	
			for m in messages1:
				if (m != '' and m != b''):
					#print(str(m)+'\n')
					decryptedMessage = privateKey.decrypt(m)
					decryptedMessage = decryptedMessage.decode('utf-8')
					writeCacheMessage(idSha, str(decryptedMessage))
					print(str(i) + ': ' + str(decryptedMessage))
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
		var = str(input("Enter Command ... \n"))
		#print(var)
		#add help
		if var == '1':
			sendMessage(s)
			continue
		elif var == '2':
			getMessage(s)
			continue
		elif var == '3':
			loadKey()
			continue
		elif var == '4':
			generateKey()
			continue
		elif var == '7':
			readCacheMessage()
			continue
		elif var == '9':
			cryptTest()
			continue
		elif var == '0':
			s.close() #Connection to Masterserver closed
			break
		elif var == 'h' or var == 'H' or var == 'help' or var == 'Help':
			print('Press 1 for sending a message.')
			print('Press 2 for recieving new messages.')
			print('Press 3 for loading the keys (debug).')
			print('Press 4 for genearting new keys (debug).')
			print('Press 9 for a crypting test. (debug).')
			print('Press 0 for closing the connection.')
		else:
			print('Unknown command. Press h for help.')
			continue


start()

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
from os import walk
import time
from time import sleep
import argparse

def generateKey():
	if (not os.path.exists('./ownKey')):
		os.makedirs('./ownKey')

	random_generator = Random.new().read
	key = RSA.generate(1024, random_generator)
	f = open("./ownKey/key.txt", "w")
	f.write(key.exportKey().decode('utf-8'))
	f.close()
	publickey = key.publickey()
	f = open("./ownKey/publickey.txt", "w")
	f.write(key.publickey().exportKey().decode('utf-8'))
	f.close()

def generatePublicKeys():
	if (not os.path.exists('./publickeys')):
		os.makedirs('./publickeys')

	for i in range(0, 10):
		random_generator = Random.new().read
		key = RSA.generate(1024, random_generator)
		f = open("./publickeys/key" + str(i) + ".txt", "w")
		f.write(key.exportKey().decode('utf-8'))
		f.close()
		publickey = key.publickey()
		f = open("./publickeys/publickey" + str(i) + ".txt", "w")
		f.write(key.publickey().exportKey().decode('utf-8'))
		f.close()


def loadOwnKey():
	f = open("./ownKey/key.txt", "r")
	key = RSA.importKey(f.read())
	f.close()
	f = open("./ownKey/publickey.txt", "r")
	publicKey = RSA.importKey(f.read())
	f.close()
	return (key, publicKey)

def loadKey(path):
	f = open("./publickeys/" + path, "r")
	publicKey = RSA.importKey(f.read())
	f.close()
	return (publicKey)


def calculateOwnID():
	f = open("./ownKey/publickey.txt", "rb")
	sha1 = hashlib.sha1()
	try:
		sha1.update(f.read())
	finally:
		f.close()
	return sha1.hexdigest()


def calculateID(path):
	f = open("./publickeys/" + path, "rb")
	sha1 = hashlib.sha1()
	try:
		sha1.update(f.read())
	finally:
		f.close()
	return sha1.hexdigest()


def writeCacheMessage(idSha, msg):
	ms = int(time.time()*1000000)
	checksum = hashlib.md5()
	checksum.update(str(len(msg)).encode('utf-8'))
	fileName = checksum.hexdigest() + "-" + str(ms) + ".txt"
	#print(fileName)
	if (os.path.isfile('./msg/' + idSha + '/' + fileName)):
		f = open('./msg/' + idSha + '/' + fileName, "a")
		f.write(msg)
		f.close()
	elif (not os.path.exists('./msg')):
		os.makedirs('./msg')
		os.makedirs('./msg/' + idSha)
		f = open('./msg/' + idSha + '/' + fileName, "w")
		f.write(msg)
		f.close()
	elif (not os.path.exists('./msg/' + idSha)):
		os.makedirs('./msg/' + idSha)
		f = open('./msg/' + idSha + '/' + fileName, "w")
		f.write(msg)
		f.close()
	else:
		f = open('./msg/' + idSha + '/' + fileName, "w")
		f.write(msg)
		f.close()


def readCacheMessage():
	shaID = calculateOwnID()
	if (os.path.exists('./msg/' + shaID)):
		for file in os.listdir('./msg/' + shaID):
			if file.endswith(".txt"):
				f = open ('./msg/' + shaID + '/' + file, "r")
				print(f.read())
				f.close()
	else:
		print('No cached messages are available.')


def printMessages(messages, idSha):
	keys = loadOwnKey()
	privateKey = keys[0]
	publicKey = keys[1]

	counter = 1

	for m in messages:
		if (m != '' and m != b''):
			#print(str(m)+'\n')
			decryptedMessage = privateKey.decrypt(m)
			decryptedMessage = decryptedMessage.decode('utf-8')
			writeCacheMessage(idSha, str(decryptedMessage))
			print(str(counter) + ': ' + str(decryptedMessage))
			counter = counter+1
	

def cryptTest():
	keys = loadOwnKey()
	privateKey = keys[0]
	publicKey = keys[1]
	
	encrypt = publicKey.encrypt('encrypt this message'.encode('utf-8'), 32)
	print('encrypted message: ', encrypt, '\n')

	decrypt = privateKey.decrypt(ast.literal_eval(str(encrypt)))
	print('decrypted: ', decrypt)


def sendMessage(server):
	if (not os.path.exists('./publickeys')):
		print('Please add publickeys to the folder "./publickeys" for sending a message.')
	else:
		f = []
		for (dirpath, dirnames, filenames) in walk('./publickeys'):
			f.extend(filenames)
			break

		f.sort()

		print('Available keys are:')
		for file in f:
			print(file)

		wantedKey = str(input("Please type the name of the key.\n"))

		if (os.path.isfile('./publickeys/' + wantedKey) or os.path.isfile('./publickeys/' + wantedKey + '.txt')):
			if not wantedKey.endswith('.txt'):	
				wantedKey = wantedKey + '.txt'

			publicKey = loadKey(wantedKey)

			message = ''
			print("Enter the message:")
			#message = str(input("Enter:"))

			while (True):
				try:
					message += str(input())
					message += '\n'
			
				except EOFError:
		   			 break

			message = message[:-1]

			#print(message)
			encryptedMessage = publicKey.encrypt(message.encode('utf-8'), 32)

			send = encryptedMessage[0]
			#print(encryptedMessage[0])
			send += b'###'
			#print(send + b'\n')

			list1 = list(bytearray(send))
			#print(list1)
	
			base = base64.b64encode(send)
			#print(base + b'\n')

			idSha = calculateID(wantedKey)
			#print(idSha)

			command = bytes('NEMSG:' + idSha + ':', 'utf8')
			command += base
			#print(command)

			server.send(command)
			resp = server.recv(100000)
			#print(resp)

			if resp == b'NEMSG:OK\n':
				print('Sending message succesfull.')
			else:
				print('Something went wrong while sending the messsage. Try again later.')
					
		else:
			print(wantedKey + ' is not a file.')


def getMessage(master):
	master.send(bytes('GTSRV', 'utf8'))
	serverList = master.recv(100000)
	if serverList.startswith(b'GTSRV:'):
		#print(serverList)
		serverList = serverList[7:-2]
		#print(serverList)
		serverList = serverList.split(b';')
		#print(serverList)

		if(len(serverList) < 2):
			print('Not enough serves available. Please try again later.')
		else:
			slave1 = random.choice(serverList)
			#print(slave1)
			del serverList[serverList.index(slave1)]
			slave2 = random.choice(serverList)
			#print(serverList)
			#print(slave2)

			server1 = serverConnection(slave1.split(b',')[0], int(slave1.split(b',')[1]))
			server2 = serverConnection(slave2.split(b',')[0], int(slave2.split(b',')[1]))
	
			idSha = calculateOwnID()

			master.send(bytes('GTADD', 'utf-8'))
			listAvailableIDs = master.recv(100000)
			if listAvailableIDs.startswith(b'GTADD:'):
				listAvailableIDs = listAvailableIDs[7:-2]
				#print(listAvailableIDs)

				arrayAvailableIDs = listAvailableIDs.split(b';')
				arrayAvailableIDs.sort()
			
				#print(arrayAvailableIDs)

				if (bytes(idSha, 'utf-8') not in arrayAvailableIDs):
					print('Sorry, there are no messages for you available.')
				else:
					#del arrayAvailableIDs[arrayAvailableIDs.index(bytes(idSha, 'utf-8'))]
					length = 0
	
					indexID = arrayAvailableIDs.index(bytes(idSha, 'utf-8'))
					#print(indexID)		
					availableIDs = len(arrayAvailableIDs)
					#print(availableIDs)

					if (availableIDs < 3):
						print('There is no privacy available.')
						var = str(input("Do you want to continue with no privacy?[y|n]\n"))
						if var == 'y' or var == 'Y':
							bitVector1 = ""
							while (length < availableIDs):
								if (length == indexID):
									bitVector1 += "1"
								else:
									bitVector1 += "0"
								length += 1

							server1.send(bytes('GTMSG:{' + bitVector1 + '}', 'utf8'))
							message1 = server1.recv(100000000)
							if message1.startswith(b'GTMSG:OK:'):
								message1 = message1[9:-1]
								message1 = base64.b64decode(message1)
								messages1 = message1.split(b'###')

								printMessages(messages1, idSha)
							else:
								print('Something went wrong while getting the messages. Try again later.')


						elif var == 'n' or var == 'N':
							print('Operation canceled.')
						else:
							print('Unknown command. Operation canceled.')
			

					else:
						bitVector1 = ""
						bitVector2 = ""
						#print(bitVector1)
						#print(bitVector2)
	
						while (length < availableIDs):
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

						server1.send(bytes('GTMSG:{' + bitVector1 + '}', 'utf8'))
						server2.send(bytes('GTMSG:{' + bitVector2 + '}', 'utf8'))
						message1 = server1.recv(1000000000)
						message2 = server2.recv(1000000000)
						if message1.startswith(b'GTMSG:OK:') and message2.startswith(b'GTMSG:OK:'):
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
		
							printMessages(messages1, idSha)
						else:
							print('Something went wrong while getting the messages. Try again later.')
			else:
				print('Something went wrong while trying to get available IDs. Try again later.')
				server1.close()
				server2.close()	
	else:
		print('Something went wrong while trying to get available servers. Try again later.')		




def serverConnection(host, port):
	s = socket.socket()
	#host = socket.gethostname()

	try:
		s.connect((host, port))
		print('Connected to server ' + str(host) + ':' + str(port));
	except socket.error as exc:
		print('Cannot connect to server ' + str(host) + ':' + str(port) + '. Reason: ' + str(exc));
	return s


def pingTest(master):
	try:
		master.send(bytes('SPING:1', 'utf8'))
		message = master.recv(100000000)
		if message.startswith(b'SPING:'):
			return True
		else:
			return False
	except socket.error as exc:
		print('PING to Masterserver failed. Reason: ' + str(exc) + '. Trying to reconnect.');



def start():
	ip = '127.0.0.1'
	port = 6667
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--ip", help="IP to Materserver")
	parser.add_argument("-p", "--port", help="specify the Port to Masterserver", type=int)
	args = parser.parse_args()
	if args.ip:
		ip = args.ip
	if args.port:
		port = args.port
		print(port)
	s = serverConnection(ip, port) #Masterserver

	while True:
		if pingTest(s):
			var = str(input("Enter Command ... \n"))
			#print(var)
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
			elif var == '6':
				generatePublicKeys()
				continue
			elif var == '7':
				readCacheMessage()
				continue
			elif var == '8':
				pingTest(s)
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
				print('Press 4 for generating new keys (debug).')
				print('Press 6 for generating 10 new public keys (debug).')
				print('Press 7 for printing cached messages (debug).')
				print('Press 8 for a PING test to Masterserver (debug).')
				print('Press 9 for a crypting test. (debug).')
				print('Press 0 for closing the connection.')
			else:
				print('Unknown command. Press h for help.')
				continue
		else:
			s = serverConnection(ip, port) #Masterserver
			sleep(2);

start()

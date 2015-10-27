#!/usr/bin/micropython
import sys
from libs import struct, time, os, random, re, binascii
import usocket as socket

# CONFIG
server = "1.1.1.1"
username = ""
password = ""
host_name = "fuyumi"
host_os = "TRANS-AM"
host_ip = '2.2.2.2'
dhcp_server = '3.3.3.3'
mac = 0xb888e3051680
CONTROLCHECKSTATUS = '\x20'
ADAPTERNUM = '\x05'
KEEP_ALIVE_VERSION = '\xd8\x02'
AUTH_VERSION = '\x25\x00'
IPDOG = '\x01'
# CONFIG_END

class ChallengeException (Exception):
	def __init__(self):
		pass

class LoginException (Exception):
	def __init__(self):
		pass

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
addr = socket.getaddrinfo(server, 61440)[0][4]
addr2 = socket.getaddrinfo('0.0.0.0', 61440)[0][4]
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(addr2)
# s.settimeout(3)
s.connect(addr)

#s.settimeout(3)
SALT = ''
IS_TEST = True
# specified fields based on version
CONF = "/etc/drcom.conf"
if IS_TEST:
	CONF = ''
UNLIMITED_RETRY = False
EXCEPTION = True
DEBUG = False #log saves to file
LOG_PATH = '/var/log/drcom_client.log'
if IS_TEST:
	DEBUG = True
	LOG_PATH = 'drcom_client.log'


def log(*args, **kwargs):
	s = ' '.join(args)
	print (s)
	if DEBUG:
	  with open(LOG_PATH,'a') as f:
		  f.write(s + '\n')

def challenge(svr,ran):
	while True:
		t = struct.pack("<H", int(ran)%(0xFFFF))
		s.send(b"\x01\x02" + t +b"\x09" + b"\x00"*15)
		try:
			data = s.recv(1024)
			log('[challenge] recv',str(data))
			break
		except:
			log('[challenge] timeout, retrying...')
			time.sleep(1)
			continue
		
		# if address == (svr, 61440):
		# 	break
		# else:
		# 	continue
	log('[DEBUG] challenge:\n' + str(data))
	if data[:1] != b'\x02':
	  raise ChallengeException
	log('[challenge] challenge packet sent.')
	return data[4:8]

def md5sum(s):
	# m = md5.digest(s)
	var = s.decode('utf-8')
	with open('/tmp/drcom_var', 'wb') as f:
		f.write(var)
	os.system('./md5')
	with open('/tmp/drcom_md5', 'r') as f:
		foo = f.read().strip()
	bar = binascii.unhexlify(foo)
	# print (bar)
	return bar

def dump(n):
	s = '%x' % n
	if len(s) & 1:
		s = '0' + s
	s = binascii.unhexlify(bytes(s,'utf-8'))
	return s

def ror(md5, pwd):
	ret = ''
	for i in range(len(pwd)):
		x = ord(md5[i]) ^ ord(pwd[i])
		ret += chr(((x<<3)&0xFF) + (x>>5))
	return ret

def keep_alive_package_builder(number,random,tail,type=1,first=False):
	data = '\x07'+ chr(number) + '\x28\x00\x0b' + chr(type)
	if first :
	  data += '\x0f\x27'
	else:
	  data += KEEP_ALIVE_VERSION
	data += '\x2f\x12' + '\x00' * 6
	data += tail
	data += '\x00' * 4
	#data += struct.pack("!H",0xdc02)
	if type == 3:
		foo = ''.join([chr(int(i)) for i in host_ip.split('.')]) # host_ip
		#CRC
		# edited on 2014/5/12, filled zeros to checksum
		# crc = packet_CRC(data+foo)
		crc = '\x00' * 4
		#data += struct.pack("!I",crc) + foo + '\x00' * 8
		data += crc + foo + '\x00' * 8
	else: #packet type = 1
		data += '\x00' * 16
	return data

def packet_CRC(s):
	ret = 0
	for i in re.findall('..', s):
		ret ^= struct.unpack('>h', i)[0]
		ret &= 0xFFFF
	ret = ret * 0x2c7
	return ret

def keep_alive2(*args):
	#first keep_alive:
	#number = number (mod 7)
	#status = 1: first packet user sended
	#         2: first packet user recieved
	#         3: 2nd packet user sended
	#         4: 2nd packet user recieved
	#   Codes for test
	tail = ''
	packet = ''
	svr = server
	ran = random.randint(0,0xFFFF)
	ran += random.randint(1,10)
	# 2014/10/15 add by latyas, maybe svr sends back a file packet
	svr_num = 0
	packet = keep_alive_package_builder(svr_num,dump(ran),'\x00'*4,1,True)
	while True:
		log('[keep-alive2] send1',str(packet))
		s.send(packet)
		data = s.recv(1024)
		log('[keep-alive2] recv1',str(data))
		if data.startswith('\x07\x00\x28\x00') or data.startswith('\x07' + chr(svr_num)  + '\x28\x00'):
			break
		elif data[:1] == '\x07' and data[2:3] == '\x10':
			log('[keep-alive2] recv file, resending..')
			svr_num = svr_num + 1
			packet = keep_alive_package_builder(svr_num,dump(ran),'\x00'*4,1, False)
		else:
			log('[keep-alive2] recv1/unexpected',str(data))
	#log('[keep-alive2] recv1',data.encode('hex'))
	
	ran += random.randint(1,10)   
	packet = keep_alive_package_builder(svr_num, dump(ran),'\x00'*4,1,False)
	log('[keep-alive2] send2',str(packet))
	s.send(packet)
	while True:
		data = s.recv(1024)
		if data[:1] == '\x07':
			svr_num = svr_num + 1
			break
		else:
			log('[keep-alive2] recv2/unexpected',str(data))
	log('[keep-alive2] recv2',str(data))
	tail = data[16:20]
	

	ran += random.randint(1,10)   
	packet = keep_alive_package_builder(svr_num,dump(ran),tail,3,False)
	log('[keep-alive2] send3',str(packet))
	s.send(packet)
	while True:
		data = s.recv(1024)
		if data[:1] == '\x07':
			svr_num = svr_num + 1
			break
		else:
			log('[keep-alive2] recv3/unexpected',str(data))
	log('[keep-alive2] recv3',str(data))
	tail = data[16:20]
	log("[keep-alive2] keep-alive2 loop was in daemon.")
	
	i = svr_num
	while True:
		try:
			ran += random.randint(1,10)   
			packet = keep_alive_package_builder(i,dump(ran),tail,1,False)
			#log('DEBUG: keep_alive2,packet 4\n',packet.encode('hex'))
			log('[keep_alive2] send',str(i),str(packet))
			s.send(packet)
			data = s.recv(1024)
			log('[keep_alive2] recv',str(data))
			tail = data[16:20]
			#log('DEBUG: keep_alive2,packet 4 return\n',data.encode('hex'))
		
			ran += random.randint(1,10)   
			packet = keep_alive_package_builder(i+1,dump(ran),tail,3,False)
			#log('DEBUG: keep_alive2,packet 5\n',packet.encode('hex'))
			s.send(packet)
			log('[keep_alive2] send',str(i+1),str(packet))
			data = s.recv(1024)
			log('[keep_alive2] recv',str(data))
			tail = data[16:20]
			#log('DEBUG: keep_alive2,packet 5 return\n',data.encode('hex'))
			i = (i+2) % 0xFF
			time.sleep(20)
			keep_alive1(*args)
		except:
			pass


def checksum(s):
	ret = 1234
	for i in re.findall('....', s):
		data = b''
		for x in range(len(s),0,-1):
			data += (i[x-1:x])
		ret ^= int(binascii.hexlify(data),16)
	ret = (1968 * ret) & 0xffffffff
	return struct.pack('<I', ret)

def mkpkt(salt, usr, pwd, mac):
	data = b'\x03\x01\x00'+chr(len(usr)+20)
	data += md5sum(b'\x03\x01'+salt+pwd)
	data += (usr + 36*'\x00')[:36]
	data += CONTROLCHECKSTATUS
	data += ADAPTERNUM
	data += (6*b'\x00' + dump((int(binascii.hexlify(data[4:10]), 16))^mac))[-6:] #mac xor md51
	data += md5sum(b"\x01" + pwd + salt + b'\x00'*4) #md52
	data += b'\x01' # number of ip
	#data += '\x0a\x1e\x16\x11' #your ip address1, 10.30.22.17
	data += b''.join([bytes([int(i)]) for i in host_ip.split('.')]) #x.x.x.x -> 
	data += '\00'*4 #your ipaddress 2
	data += '\00'*4 #your ipaddress 3
	data += '\00'*4 #your ipaddress 4
	data += md5sum(data + b'\x14\x00\x07\x0b')[:8] #md53
	data += IPDOG
	data += b'\x00'*4 #delimeter
	data += (host_name + 32*'\x00')[:32]
	data += b'\x08\x08\x08\x08' #primary dns: 8.8.8.8
	data += b''.join([bytes([int(i)]) for i in dhcp_server.split('.')]) #DHCP server
	data += b'\x00\x00\x00\x00' #secondary dns:0.0.0.0
	data += b'\x00' * 8 #delimeter
	data += b'\x94\x00\x00\x00' # unknow
	data += b'\x05\x00\x00\x00' # os major
	data += b'\x01\x00\x00\x00' # os minor
	data += b'\x28\x0a\x00\x00' # OS build
	data += b'\x02\x00\x00\x00' #os unknown
	data += (host_os + 32*'\x00')[:32]
	data += b'\x00' * 96
	#data += '\x01' + host_os.ljust(128, '\x00')
	#data += '\x0a\x00\x00'+chr(len(pwd)) # \0x0a represents version of client, algorithm: DRCOM_VER + 100
	#data += ror(md5sum('\x03\x01'+salt+pwd), pwd)
	data += AUTH_VERSION
	data += b'\x02\x0c'
	data += checksum(data+b'\x01\x26\x07\x11\x00\x00'+dump(mac))
	data += b'\x00\x00' #delimeter
	data += dump(mac)
	data += b'\x00' # auto logout / default: False
	data += b'\x00' # broadcast mode / default : False
	data += b'\xe9\x13' #unknown, filled numbers randomly =w=
	
	log('[mkpkt]',str(data))
	return data

def login(usr, pwd, svr):
	global SALT
 
	i = 0
	while True:
		salt = challenge(svr,time.time()+random.randint(0xF,0xFF))
		SALT = salt
		packet = mkpkt(salt, usr, pwd, mac)
		log('[login] send',str(packet))
		s.send(packet)
		data = s.recv(1024)
		log('[login] recv',str(data))
		log('[login] packet sent.')
		# if address == (svr, 61440):
		if data[:1] == '\x04':
			log('[login] loged in')
			break
		else:
			if i >= 5 and UNLIMITED_RETRY == False :
				log('[login] exception occured.')
				sys.exit(1)
			else:
				continue
			
	log('[login] login sent')
	#0.8 changed:
	return data[23:39]
	#return data[-22:-6]

def keep_alive1(salt,tail,pwd,svr):
	foo = struct.pack('!H',int(time.time())%0xFFFF)
	data = '\xff' + md5sum('\x03\x01'+salt+pwd) + '\x00\x00\x00'
	data += tail
	data += foo + '\x00\x00\x00\x00'
	log('[keep_alive1] send',str(data))

	s.send(data)
	while True:
		data = s.recv(1024)
		if data[:1] == '\x07':
			break
		else:
			log('[keep-alive1]recv/not expected',str(data))
	log('[keep-alive1] recv',str(data))

def empty_socket_buffer():
#empty buffer for some fucking schools
	log('starting to empty socket buffer')
	try:
		while True:
			data = s.recv(1024)
			log('recived sth unexpected',str(data))
			if s == '':
				break
	except:
		# get exception means it has done.
		log('exception in empty_socket_buffer')
		pass
	log('emptyed')
def daemon():
	with open('/var/run/jludrcom.pid','w') as f:
		f.write(str(os.getpid()))
		
def main():
	if not IS_TEST:
		daemon()
		execfile(CONF, globals())
	log("auth svr:"+server+"\nusername:"+username+"\npassword:"+password+"\nmac:"+str(hex(mac)))
	while True:
		try:
			package_tail = login(username, password, server)
		except LoginException:
			continue
		log('package_tail',str(package_tail))
		#keep_alive1 is fucking bullshit!
		empty_socket_buffer()
		keep_alive1(SALT,package_tail,password,server)
		keep_alive2(SALT,package_tail,password,server)
if __name__ == "__main__":
	main()

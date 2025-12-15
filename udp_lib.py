#!/usr/bin/env python3
# -*- coding: utf_8 -*-

import socket
from time import sleep
from random import randint
from threading import Thread
from secrets import token_bytes
from nacl.signing import SigningKey

from .schemes_lib import Schemes
from .bytes_lib import BytesReader
from .encryption_lib import (
	get_public_key,
	get_secret,
	sign_message,
	aes_encrypt_with_secret,
	aes_decrypt_with_secret,
	create_aes_cipher,
	create_aes_params,
	parse_aes_params,
	create_aes_ciphers
)
from .utils_lib import (
	sha256,
	get_peer_id,
	get_method_id,
	create_udp_url,
	parse_udp_url,
	get_time_str,
	get_milli_time,
	bcolors,
	Dict
)


SCHEMES_TEXT = """
encrypted_message = message_len:uint16, scheme_ver:uint16, method_id:#2, message_id:#4, nonce:#32, data_len:uint16, data:#data_len, checksum:#32, random_len:uint8, random_bytes:#random_len
message = message_len:uint16, scheme_ver:uint16, peer_id:#32, local_pub:#32, method_id:#2, message_id:#4, data_len:uint16, data:#data_len, checksum:#32, random_len:uint8, random_bytes:#random_len
handshake = encrypted_aes_params:#96, checksum:#32
"""


class UdpPeer:
	def __init__(self, udp, addr, pubkey):
		self.udp = udp
		self.addr = addr
		self.pubkey = pubkey
		self.id = get_peer_id(pubkey)
		self.incoming_messages = dict()
		self.incoming_encrypted_messages = dict()
		self.last_ping_time = 0
		self.last_connecting_time = 0
		self.last_connected_time = 0
		self.buff = Dict()
		self.create_milli_time = get_milli_time()
		self.delta_connect_time = 1000 # ms
		self.delta_ping_time = 300 # ms

		self.statistics = Dict()
		self.statistics.pings_ok = 0
		self.statistics.connects_ok = 0
		self.statistics.connects_error = 0
	#end define

	def send_message(self, method_name, data):
		#print("send_message data:", data.hex())
		message_id = token_bytes(4)
		message = self.udp.create_message(self.id, self.udp.local_pub, message_id, method_name, data)
		self.udp.sock.sendto(message, self.addr)
		#print(f"send_message - addr: {self.addr}, data: {data.hex()}, message_len: {len(message)}, message: {message.hex()}")
		return message_id
	#end define

	def send_response(self, message_id, data):
		method_name = "response"
		message = self.udp.create_message(self.id, self.udp.local_pub, message_id, method_name, data)
		self.udp.sock.sendto(message, self.addr)
		#print(f"send_response - addr: {self.addr}, data: {data.hex()}, message_len: {len(message)}, message: {message.hex()}")
	#end define

	def send_encrypted_message(self, method_name, data=b''):
		message_id = token_bytes(4)
		message = self.udp.create_encrypted_message(self.tx_cipher, message_id, method_name, data)
		self.udp.sock.sendto(message, self.addr)
		#print(f"send_encrypted_message - addr: {self.addr}, data: {data.hex()}, message_len: {len(message)}, message: {message.hex()}")
		return message_id
	#end define

	def send_encrypted_response(self, message_id, data):
		method_name = "response"
		message = self.udp.create_encrypted_message(self.tx_cipher, message_id, method_name, data)
		self.udp.sock.sendto(message, self.addr)
		#print(f"send_encrypted_response - addr: {self.addr}, data: {data.hex()}, message_len: {len(message)}, message: {message.hex()}")
	#end define

	def read_message(self, message_id):
		#print("read_message")
		return self.read_message_process(message_id, self.incoming_messages)
	#end define

	def read_encrypted_message(self, message_id):
		#print("read_encrypted_message")
		return self.read_message_process(message_id, self.incoming_encrypted_messages)
	#end define

	def read_message_process(self, message_id, data):
		for i in range(3):
			sleep(0.1)
			#print("read_message_process - peer:", id(self), "in_data:", [item.hex() for item in data.keys()])
			message = data.get(message_id)
			if message != None:
				data.pop(message_id)
				return message
		#print("read_message_process timeout:", message_id.hex())
	#end define

	def ping(self):
		method_name = "ping"
		random_bytes = token_bytes(8)
		message_id = self.send_encrypted_message(method_name, random_bytes)
		response = self.read_encrypted_message(message_id)
		if response != random_bytes:
			#print(f"UdpPeer.ping error: response != random_bytes. random_bytes: {random_bytes.hex()}, response: {response.hex() if response else response}")
			return False
		self.set_ping_time()
		return True
	#end define

	def ping_ok(self):
		self.statistics.pings_ok += 1
		self.delta_connect_time = int(self.delta_connect_time//1.1)
		if self.delta_connect_time < 1000:
			self.delta_connect_time = 1000
	#end define

	def run(self):
		Thread(target=self.ping_thr).start()
	#end define

	def ping_thr(self):
		while self.is_allive():
			sleep(self.delta_ping_time/1000) # ms to sec
			ping_result = self.ping()
			self.ping_ok()
			#print("ping", get_time_str(), self.addr, "-->", ping_result)
		self.connection_error()
	#end define

	def connection_ok(self):
		self.statistics.connects_ok += 1
	#end define

	def connection_error(self):
		print(bcolors.red, "Сonnection broken:", self.addr, bcolors.endc)
		self.delta_connect_time *= 2
		self.statistics.connects_error += 1
	#end define

	def set_ciphers(self, rx_cipher, tx_cipher):
		self.rx_cipher = rx_cipher
		self.tx_cipher = tx_cipher
	#end define

	def get_ciphers(self):
		return self.rx_cipher, self.tx_cipher
	#end define

	def set_ping_time(self):
		self.last_ping_time = get_milli_time()
	#end define

	def get_milli_ping_ago(self):
		now = get_milli_time()
		ago = now - self.last_ping_time
		return ago
	#end define

	def set_connected_time(self):
		self.last_connected_time = get_milli_time()
	#end define

	def get_milli_connected_ago(self):
		now = get_milli_time()
		ago = now - self.last_connected_time
		return ago
	#end define

	def set_connecting_time(self):
		self.last_connecting_time = get_milli_time()
	#end define

	def get_milli_connecting_ago(self):
		now = get_milli_time()
		ago = now - self.last_connecting_time
		return ago
	#end define

	def is_allive(self):
		return self.get_milli_connected_ago() < 1000 or self.get_milli_ping_ago() < 1000
	#end define

	def is_ready_to_connect(self):
		return self.get_milli_connecting_ago() > self.delta_connect_time and self.is_allive() == False
	#end define
#end class

class UdpSocket:
	def __init__(self, local_priv, port):
		# local_priv = SigningKey.generate().encode() # 32 bytes ed25519
		self.port = port
		self.local_priv = local_priv
		self.local_pub = get_public_key(local_priv)
		self.local_id = get_peer_id(self.local_pub)
		self.sock = self.create_socket()
		self.peers = dict()
		self.schemes = Schemes(SCHEMES_TEXT)
		self.reactions = dict()

		#self.add_reaction("ping", self.ping_reaction)
		#self.add_reaction("response", self.response_reaction)

		Thread(target=self.receiving_thr).start()
		Thread(target=self.cleaning_thr).start()

		print(bcolors.blue, "Start udp_socket on port:", port, bcolors.endc)
	#end define

	def create_socket(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.settimeout(0.3)
		sock.bind(('', self.port))
		return sock
	#end define

	def get_url(self, host):
		return create_udp_url(host, self.port, self.local_pub)
	#end define

	def connect(self, addr, peer_pub):
		peer = self.get_incoming_peer(addr, peer_pub)
		if not peer.is_ready_to_connect():
			print(f"Connect error to {peer.addr} - not ready")
			return
		peer.set_connecting_time()

		print(bcolors.blue, "Connecting:", addr, bcolors.endc)
		handshake, aes_params = self.create_handshake(peer_pub)
		rx_cipher, tx_cipher = create_aes_ciphers(aes_params)
		peer.set_ciphers(rx_cipher, tx_cipher)

		message_id = peer.send_message("handshake", handshake)
		response = peer.read_message(message_id)
		if response != b"ok":
			print(f"Connect error to {peer.addr} - bad response: {response.hex() if response else response}")
			peer.connection_error()
			return
		#end if

		peer.set_connected_time()
		peer.run()
		print(bcolors.blue, "Established connection", peer.addr, bcolors.endc)
		peer.connection_ok()

		return peer
	#end define

	def receiving_thr(self):
		while True:
			try:
				message, addr = self.sock.recvfrom(1024)
				self.incoming_reaction(addr, message)
			except socket.timeout:
				continue
			except Exception as ex:
				print(bcolors.red, "Receiving exception:", ex, bcolors.endc)
		#end while
	#end define

	def cleaning_thr(self):
		delta = 24 *3600 *1000
		while True:
			for addr, peer in self.peers.copy().items():
				if peer.delta_connect_time < delta:
					continue
				print("cleaning_thr", addr)
				self.peers.pop(addr)
			sleep(30)
		#end while
	#end define

	def get_incoming_peer(self, addr, peer_pub):
		peer = self.peers.get(addr)
		if peer != None and peer.pubkey == peer_pub:
			return peer
		peer = UdpPeer(self, addr, peer_pub)
		self.peers[addr] = peer
		return peer
	#end define

	def incoming_reaction(self, addr, message):
		#print('\n' + "received message from:", addr, "len:", len(message), "message:", message.hex())
		peer = self.peers.get(addr)
		if peer and peer.is_allive():
			self.incoming_encrypted_message(peer, message)
		else:
			self.incoming_message(addr, message)
	#end define

	def incoming_message(self, addr, message):
		response = None
		parse_result = self.parse_message(addr, message)
		if parse_result == None:
			print(f"incoming_message from {addr} - not parsed")
			return
		#end define

		local_id, peer_pub, method_id, message_id, message = parse_result
		peer = self.get_incoming_peer(addr, peer_pub)
		
		if method_id == get_method_id("handshake"):
			response = self.incoming_handshake(peer, message)
		elif method_id == get_method_id("response"):
			self.response_reaction(peer, message_id, message)
		else:
			print(f"incoming_message from {addr} - unknown method: {method_id.hex()}")
		#end if

		if response != None:
			peer.send_response(message_id, response)
	#end define

	def incoming_handshake(self, peer, message):
		reader = BytesReader(message)
		aes_params = self.parse_handshake(peer, reader)
		if aes_params == None:
			print("incoming_handshake error: not parsed")
			return
		#end define

		tx_cipher, rx_cipher = create_aes_ciphers(aes_params)
		self.peers[peer.addr] = peer
		peer.set_ciphers(rx_cipher, tx_cipher)
		peer.set_connecting_time()
		peer.set_connected_time()
		
		print(bcolors.blue, "Established incoming connection", peer.addr, bcolors.endc)
		peer.connection_ok()
		response = b"ok"
		return response
	#end define

	def response_reaction(self, peer, message_id, message):
		#print("response_reaction - peer:", id(peer), "message_id:", message_id.hex(), "message:", message.hex())
		peer.incoming_messages[message_id] = message
		#print(f"response_reaction - incoming_messages:", [item.hex() for item in peer.incoming_messages.keys()])
	#end define

	def incoming_encrypted_message(self, peer, encrypted_message):
		response = None
		parse_result = self.parse_encrypted_message(peer, encrypted_message)
		if parse_result == None:
			print("incoming_encrypted_message error: not parsed")
			return
		#end define

		method_id, message_id, message = parse_result
		if method_id == get_method_id("ping"):
			response = self.ping_reaction(peer, message)
		elif method_id == get_method_id("response"):
			self.encrypted_response_reaction(peer, message_id, message)
		elif method_id in self.reactions:
			reaction = self.reactions.get(method_id)
			response = reaction(udp_socket=self, peer=peer, message=message)
		#end if

		if response != None:
			peer.send_encrypted_response(message_id, response)
	#end define

	def encrypted_response_reaction(self, peer, message_id, message):
		#print("encrypted_response_reaction - peer:", id(peer), "message_id:", message_id.hex(), "message:", message.hex())
		peer.incoming_encrypted_messages[message_id] = message
		#print(f"encrypted_response_reaction - incoming_encrypted_messages:", [item.hex() for item in peer.incoming_encrypted_messages.keys()])
	#end define

	def ping_reaction(self, peer, message):
		#print("pong", peer.addr, get_time_str())
		peer.set_ping_time()
		peer.ping_ok()
		return message
	#end define

	def add_reaction(self, name, func):
		method_id = get_method_id(name)
		if name in self.reactions:
			raise Exception("UdpPeer.add_reaction error: method alreade exist")
		self.reactions[method_id] = func
	#end define

	def create_handshake(self, peer_pub):
		scheme = self.schemes.get("handshake")
		secret = get_secret(self.local_priv, peer_pub) # 32 bytes
		aes_params = token_bytes(96) #32+32+16+16
		checksum = sha256(aes_params)
		encrypted_aes_params = aes_encrypt_with_secret(aes_params, secret)
		handshake = scheme.serialize(encrypted_aes_params=encrypted_aes_params, checksum=checksum)
		#print(f"create_handshake - aes_params: {aes_params.hex()}, encrypted_aes_params: {encrypted_aes_params.hex()}, checksum: {checksum.hex()}, ")
		return handshake, aes_params
	#end define

	def parse_handshake(self, peer, reader):
		scheme = self.schemes.get("handshake")
		handshake = scheme.deserialize(reader)
		secret = get_secret(self.local_priv, peer.pubkey)
		aes_params = aes_decrypt_with_secret(handshake.encrypted_aes_params, secret, handshake.checksum)
		#print(f"parse_handshake - aes_params: {aes_params.hex()}, encrypted_aes_params: {handshake.encrypted_aes_params.hex()}, checksum: {handshake.checksum.hex()}, ")
		if handshake.checksum != sha256(aes_params):
			print(f"parse_handshake from {peer.addr} - bad checksum")
			return
		#enf if

		return aes_params
	#end define

	def create_message(self, peer_id, local_pub, message_id, method_name, data):
		scheme = self.schemes.get("message")
		method_id = get_method_id(method_name)
		data_len = len(data)
		random_len = randint(1, 50)
		random_bytes = token_bytes(random_len)
		message = scheme.serialize(scheme_ver=scheme.ver, peer_id=peer_id, local_pub=local_pub, message_id=message_id, method_id=method_id, data_len=data_len, data=data, random_len=random_len, random_bytes=random_bytes, check_is_var_exist=False)
		checksum = sha256(message)
		message = scheme.serialize(scheme_ver=scheme.ver, peer_id=peer_id, local_pub=local_pub, message_id=message_id, method_id=method_id, data_len=data_len, data=data, random_len=random_len, random_bytes=random_bytes, checksum=checksum, check_is_var_exist=False)
		message_len = len(message)
		message = scheme.serialize(scheme_ver=scheme.ver, peer_id=peer_id, local_pub=local_pub, message_id=message_id, method_id=method_id, data_len=data_len, data=data, random_len=random_len, random_bytes=random_bytes, checksum=checksum, message_len=message_len)
		return message
	#end define

	def parse_message(self, addr, message_bytes):
		scheme = self.schemes.get("message")
		message_len = BytesReader(message_bytes).show_uint16() +2
		if message_len != len(message_bytes):
			print(f"parse_message from {addr} - bad message_len: {message_len} != {len(message_bytes)}")
			return
		#end if

		message = scheme.deserialize(message_bytes)
		if scheme.ver != message.scheme_ver:
			print(f"parse_message from {addr} - bad scheme_ver: {scheme.ver} != {message.scheme_ver}")
			return
		#end if
		
		local_id = message.peer_id
		if local_id != self.local_id:
			print(f"parse_message from {addr} - bad id")
			return
		#end if

		buff_message = scheme.serialize(scheme_ver=message.scheme_ver, peer_id=message.peer_id, local_pub=message.local_pub, message_id=message.message_id, method_id=message.method_id, data_len=message.data_len, data=message.data, random_len=message.random_len, random_bytes=message.random_bytes, check_is_var_exist=False)
		if message.checksum != sha256(buff_message):
			print(f"parse_message from {addr} - bad checksum")
			return
		#end if

		peer_pub = message.local_pub
		return local_id, peer_pub, message.method_id, message.message_id, message.data
	#end define

	def create_encrypted_message(self, tx_cipher, message_id, method_name, data):
		scheme = self.schemes.get("encrypted_message")
		method_id = get_method_id(method_name)
		data_len = len(data)
		nonce = token_bytes(32)
		random_len = randint(1, 50)
		random_bytes = token_bytes(random_len)
		message = scheme.serialize(scheme_ver=scheme.ver, method_id=method_id, message_id=message_id, nonce=nonce, data_len=data_len, data=data, random_len=random_len, random_bytes=random_bytes, check_is_var_exist=False)
		checksum = sha256(message)
		message = scheme.serialize(scheme_ver=scheme.ver, method_id=method_id, message_id=message_id, nonce=nonce, data_len=data_len, data=data, random_len=random_len, random_bytes=random_bytes, checksum=checksum, check_is_var_exist=False)
		message_len = len(message)
		message = scheme.serialize(scheme_ver=scheme.ver, method_id=method_id, message_id=message_id, nonce=nonce, data_len=data_len, data=data, random_len=random_len, random_bytes=random_bytes, checksum=checksum, message_len=message_len)
		encrypted_message = tx_cipher.encrypt(message)
		return encrypted_message
	#end define

	def parse_encrypted_message(self, peer, encrypted_message):
		message_bytes = peer.rx_cipher.decrypt(encrypted_message)
		message_len = BytesReader(message_bytes).show_uint16() +2
		if message_len != len(message_bytes):
			print(f"parse_encrypted_message from {peer.addr} - bad message_len: {message_len} != {len(message_bytes)}")
			return
		#end if

		scheme = self.schemes.get("encrypted_message")
		message = scheme.deserialize(message_bytes)
		if scheme.ver != message.scheme_ver:
			print(f"parse_encrypted_message from {peer.addr} - bad scheme_ver: {scheme.ver} != {message.scheme_ver}")
			return
		#end if

		buff_message = scheme.serialize(scheme_ver=message.scheme_ver, method_id=message.method_id, message_id=message.message_id, nonce=message.nonce, data_len=message.data_len, data=message.data, random_len=message.random_len, random_bytes=message.random_bytes, check_is_var_exist=False)
		if message.checksum != sha256(buff_message):
			print(f"parse_encrypted_message from {peer.addr} - bad checksum")
			return
		#end if

		return message.method_id, message.message_id, message.data
	#end define
#end class

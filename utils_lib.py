import time
import struct
import socket
import base64
import hashlib
import fastcrc
from bytes_lib import BytesReader
import datetime as date_time_library


def ip2uint(ip):
	return struct.unpack("I", ip2bytes(ip))[0]
#end define

def uint2ip(data):
	return bytes2ip(struct.pack("I", data))
#end define

def ip2bytes(ip):
	return socket.inet_aton(ip)
#end define

def bytes2ip(data):
	return socket.inet_ntoa(data)
#end define

def sha256(data):
	return hashlib.sha256(data).digest()
#end define

def get_peer_id(pubkey):
	scheme_id = "pub.ed25519".encode("utf-8")
	result = sha256(scheme_id + pubkey)
	return result
#end define

def get_method_id(method_name):
	return crc16(method_name.encode("utf8"))
#end define

def crc16(data):
	result_int = fastcrc.crc16.xmodem(data)
	result = result_int.to_bytes(2, byteorder="little")
	return result
#end define

def crc32(data):
	result_int = fastcrc.crc32.aixm(data)
	result = result_int.to_bytes(4, byteorder="little")
	return result
#end define

def create_udp_url(host, port, pubkey):
	# magic:#2, host:#4, port:#2, pubkey:#32, checksum:#4
	magic = get_method_id("udp_url")
	#host_int = ip2int(host)
	#host_bytes = host_int.to_bytes(4, byteorder="little")
	host_bytes = ip2bytes(host)
	port_bytes = port.to_bytes(2, byteorder="little")
	data = magic + host_bytes + port_bytes + pubkey
	checksum = crc32(data)
	url_bytes = data + checksum
	url = base64.b64encode(url_bytes).decode("utf-8")
	return url
#end define

def parse_udp_url(url):
	url_bytes = base64.b64decode(url)
	if len(url_bytes) != 44:
		raise Exception("parse_udp_url error: len(url_bytes) != 44")
	reader = BytesReader(url_bytes)
	magic = reader.read(2)
	if magic != get_method_id("udp_url"):
		raise Exception("parse_udp_url error: magic does not match")
	host_bytes = reader.show(4)
	host = bytes2ip(reader.read(4))
	port_bytes = reader.show(2)
	port = reader.read_uint16()
	pubkey = reader.read(32)
	checksum = reader.read(4)
	if checksum != crc32(magic + host_bytes + port_bytes + pubkey):
		raise Exception("parse_udp_url error: checksum does not match")
	addr = (host, port)
	return addr, pubkey
#end define

def get_time_str():
	return date_time_library.datetime.utcnow().strftime("%d.%m.%Y, %H:%M:%S.%f")[:-3]
#end define

def get_milli_time():
	return int(time.time() * 1000)
#end define


class bcolors:
	'''This class is designed to display text in color format'''
	red = "\033[31m"
	green = "\033[32m"
	yellow = "\033[33m"
	blue = "\033[34m"
	magenta = "\033[35m"
	cyan = "\033[36m"
	endc = "\033[0m"
	bold = "\033[1m"
	underline = "\033[4m"
	default = "\033[39m"
#end class

class Dict(dict):
	def __init__(self, *args, **kwargs):
		for item in args:
			self._parse_dict(item)
		self._parse_dict(kwargs)
	#end define

	def _parse_dict(self, d):
		for key, value in d.items():
			if type(value) in [dict, Dict]:
				value = Dict(value)
			if type(value) == list:
				value = self._parse_list(value)
			self[key] = value
	#end define

	def _parse_list(self, lst):
		result = list()
		for value in lst:
			if type(value) in [dict, Dict]:
				value = Dict(value)
			result.append(value)
		return result
	#end define

	def __setattr__(self, key, value):
		self[key] = value
	#end define

	def __getattr__(self, key):
		return self.get(key)
	#end define
#end class

def print_table(arr):
	buff = dict()
	for i in range(len(arr[0])):
		buff[i] = list()
		for item in arr:
			buff[i].append(len(str(item[i])))
	for item in arr:
		for i in range(len(arr[0])):
			index = max(buff[i]) + 2
			text = str(item[i]).ljust(index)
			if item == arr[0]:
				text = bcolors.blue + bcolors.bold + text + bcolors.endc
			print(text, end='')
		print()
#end define

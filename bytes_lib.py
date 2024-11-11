import struct

class BytesReader:
	def __init__(self, data):
		self.data = data
		self.len = len(data)
		self.pos = 0
	#end define

	def get(self, get_len):
		new_pos = self.pos + get_len
		if new_pos > self.len:
			raise Exception(f"BytesReader error: get_len > len: ({self.pos} + {get_len}) > {self.len}")
		result = self.data[self.pos:new_pos]
		return result, new_pos
	#end define

	def read(self, read_len):
		result, new_pos = self.get(read_len)
		self.pos = new_pos
		return result
	#end define

	def show(self, show_len):
		result, new_pos = self.get(show_len)
		return result
	#end define

	def read_int8(self):
		data = self.read(1)
		return struct.unpack("b", data)[0]
	#end define

	def read_uint8(self):
		data = self.read(1)
		return struct.unpack("B", data)[0]
	#end define

	def read_int16(self):
		data = self.read(2)
		return struct.unpack("h", data)[0]
	#end define

	def read_uint16(self):
		data = self.read(2)
		return struct.unpack("H", data)[0]
	#end define

	def read_int32(self):
		data = self.read(4)
		return struct.unpack("i", data)[0]
	#end define

	def read_uint32(self):
		data = self.read(4)
		return struct.unpack("I", data)[0]
	#end define

	def show_int8(self):
		data = self.show(1)
		return struct.unpack("b", data)[0]
	#end define

	def show_uint8(self):
		data = self.show(1)
		return struct.unpack("B", data)[0]
	#end define

	def show_int16(self):
		data = self.show(2)
		return struct.unpack("h", data)[0]
	#end define

	def show_uint16(self):
		data = self.show(2)
		return struct.unpack("H", data)[0]
	#end define

	def show_uint32(self):
		data = self.show(4)
		return struct.unpack("I", data)[0]
	#end define
#end class

class BytesWriter:
	def __init__(self):
		self.data = bytes()
		self.len = 0
	#end define

	def write(self, data):
		self.data += data
		self.len += len(data)
	#end define

	def write_int8(self, data):
		self.write(struct.pack("b", data))
	#end define

	def write_uint8(self, data):
		self.write(struct.pack("B", data))
	#end define

	def write_uint16(self, data):
		self.write(struct.pack("H", data))
	#end define

	def write_uint32(self, data):
		self.write(struct.pack("I", data))
	#end define

	def write_int16(self, data):
		self.write(struct.pack("h", data))
	#end define

	def write_int32(self, data):
		self.write(struct.pack("i", data))
	#end define
#end class

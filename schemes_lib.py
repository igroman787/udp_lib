from fastcrc import crc16
from utils_lib import Dict
from bytes_lib import BytesReader, BytesWriter


class Schemes():
	def __init__(self, schemes_text):
		self.data = dict()
		lines = schemes_text.split('\n')
		for line in lines:
			scheme = Scheme(line)
			self.data[scheme.name] = scheme
	#end define

	def get(self, name):
		return self.data.get(name)
	#end define
#end class

class Scheme():
	def __init__(self, text):
		self.ver = None
		self.name = None
		self.vars = dict()
		self.buff = dict()
		self.parse(text)
	#end define

	def crc16(self, text):
		text_bytes = text.encode("utf-8")
		result = crc16.xmodem(text_bytes)
		return result
	#end define

	def parse(self, text):
		self.ver = self.crc16(text)
		end = ';'
		if end in text:
			endp = text.find(end)
			text = text[:endp]
		#end if

		sep = '='
		if sep not in text:
			return
		#end if

		buff_list = text.split('=')
		self.name = buff_list[0].strip()
		vars_text = buff_list[1]

		vars_list = vars_text.split(',')
		vars_list = [item.strip() for item in vars_list]
		for item in vars_list.copy():
			sep = ':'
			if sep not in item:
				continue
			buff = item.split(sep)
			var_name = buff[0]
			var_type = buff[1]
			self.vars[var_name] = var_type
	#end define

	def deserialize(self, reader):
		if type(reader) != BytesReader:
			reader = BytesReader(reader)
		#end if
		
		result = Dict()
		for var_name, var_type in self.vars.items():
			result[var_name] = self.deser_types(reader, var_name, var_type)
		result["@type"] = self.name
		self.buff = dict()
		return result
	#end define

	def deser_types(self, reader, var_name, var_type):
		#print("deser_types:", var_name, var_type)
		if var_type == "int8":
			var_value = reader.read_int8()
		elif var_type == "uint8":
			var_value = reader.read_uint8()
		elif var_type == "int16":
			var_value = reader.read_int16()
		elif var_type == "uint16":
			var_value = reader.read_uint16()
		elif var_type == "int32":
			var_value = reader.read_int32()
		elif var_type == "uint32":
			var_value = reader.read_uint32()
		elif var_type.startswith('#'):
			var_value = self.deser_bytes(reader, var_type)
		else:
			raise Exception(f"Scheme.deser_types error: type not found: {var_type}")
		self.buff[var_name] = var_value
		return var_value
	#end define

	def deser_bytes(self, reader, var_type):
		var_len = self.get_var_len(var_type)
		var_value = reader.read(var_len)
		return var_value
	#end define

	def serialize(self, **data):
		check_is_var_exist = data.get("check_is_var_exist", True)
		writer = BytesWriter()
		for var_name, var_type in self.vars.items():
			var_value = data.get(var_name)
			if var_value != None:
				self.ser_types(writer, var_name, var_type, var_value)
			elif var_value == None and check_is_var_exist == True:
				raise Exception(f"Scheme.serialize error: var_name not found: {var_name}")
		return writer.data
	#end define

	def ser_types(self, writer, var_name, var_type, var_value):
		#print("ser_types:", var_name, var_type, var_value)
		if var_type == "int8":
			writer.write_int8(var_value)
		elif var_type == "uint8":
			writer.write_uint8(var_value)
		elif var_type == "int16":
			writer.write_int16(var_value)
		elif var_type == "uint16":
			writer.write_uint16(var_value)
		elif var_type == "int32":
			writer.write_int32(var_value)
		elif var_type == "uint32":
			writer.write_uint32(var_value)
		elif var_type.startswith('#'):
			self.ser_bytes(writer, var_type, var_value)
		else:
			raise Exception(f"Scheme.ser_types error: var_type not found: {var_type}")
		self.buff[var_name] = var_value
	#end define

	def ser_bytes(self, writer, var_type, var_value):
		if type(var_value) != bytes:
			raise Exception(f"Scheme.ser_bytes error: var_value is not bytes: {var_value}")
		#end if

		var_len = self.get_var_len(var_type)
		data_len = len(var_value)
		if data_len != var_len:
			raise Exception(f"Scheme.ser_bytes error: data_len != var_len: {data_len} != {var_len}")
		writer.write(var_value)
	#end define

	def get_var_len(self, var_type):
		if var_type.startswith('#'):
			var_type = var_type[1:]
		if var_type.isdigit():
			var_len = int(var_type)
		else:
			var_len = self.buff.get(var_type)
		if var_len == None:
			raise Exception(f"Scheme.get_var_len error: var_type not support: {var_type}")
		return var_len
	#end define
#end class

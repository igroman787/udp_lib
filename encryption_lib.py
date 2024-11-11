import secrets
from nacl.signing import SigningKey, VerifyKey # pip3 install pynacl
from Crypto.Cipher import AES # pip3 install pycryptodome
from Crypto.Util import Counter
import x25519 # pip3 install x25519

from utils_lib import sha256
from bytes_lib import BytesReader

def sign_message(private_key, message):
	signing_key = SigningKey(private_key)
	signed_message = signing_key.sign(message)[:64]
	return signed_message
#end define

def get_secret(local_private_key, peer_public_key):
	local_signing_key = SigningKey(local_private_key)
	local_private_key_x25519 = local_signing_key.to_curve25519_private_key().encode()
	
	# create secret key
	peer_verify_key = VerifyKey(peer_public_key) # 32 bytes
	peer_public_key_x25519 = peer_verify_key.to_curve25519_public_key().encode()
	secret = x25519.scalar_mult(local_private_key_x25519, peer_public_key_x25519)
	return secret
#end define

def get_public_key(private_key):
	signing_key = SigningKey(private_key)
	public_key = signing_key.verify_key.encode()
	return public_key
#end define

def aes_encrypt_with_secret(aes_params, secret):
	aes_hash = sha256(aes_params)
	key = secret[0:16] + aes_hash[16:32]
	nonce = aes_hash[0:4] + secret[20:32]
	cipher = create_aes_cipher(key, nonce)
	result = cipher.encrypt(aes_params)
	return result
#end define

def aes_decrypt_with_secret(encrypted_data, secret, checksum):
	key = secret[0:16] + checksum[16:32]
	nonce = checksum[0:4] + secret[20:32]
	cipher = create_aes_cipher(key, nonce)
	data = cipher.decrypt(encrypted_data)
	return data
#end define

def create_aes_cipher(key, nonce):
	initial_value = int.from_bytes(nonce, "big")
	counter = Counter.new(128, initial_value=initial_value)
	cipher = AES.new(key, AES.MODE_CTR, counter=counter)
	return cipher
#end define

def create_aes_ciphers(aes_params):
	rx_key, tx_key, rx_nonce, tx_nonce = parse_aes_params(aes_params)
	rx_cipher = create_aes_cipher(rx_key, rx_nonce)
	tx_cipher = create_aes_cipher(tx_key, tx_nonce)
	return rx_cipher, tx_cipher
#end define

def create_aes_params():
	rx_key = secrets.token_bytes(32) # 32 bytes
	tx_key = secrets.token_bytes(32) # 32 bytes
	rx_nonce = secrets.token_bytes(16) # 16 bytes
	tx_nonce = secrets.token_bytes(16) # 16 bytes
	#padding = secrets.token_bytes(64) # 64 bytes
	aes_params = rx_key + tx_key + rx_nonce + tx_nonce #+ padding # 160 bytes
	return aes_params
#end define

def parse_aes_params(aes_params):
	reader = BytesReader(aes_params)
	rx_key = reader.read(32)
	tx_key = reader.read(32)
	rx_nonce = reader.read(16)
	tx_nonce = reader.read(16)
	return rx_key, tx_key, rx_nonce, tx_nonce
#end define

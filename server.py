from nacl.signing import SigningKey
import requests

from udp_lib import UdpSocket


#privkey = SigningKey.generate().encode() # 32 bytes ed25519
privkey = bytes.fromhex("0bb3710724fd176c9634311c0bdb18dc698eb046f85f15d702949aaeb01427ba")
udp_socket = UdpSocket(privkey, 7000)

#host = requests.get("https://ifconfig.me/ip").text
host = "127.0.0.1"
udp_url = udp_socket.get_url(host)
print("url:", udp_url)

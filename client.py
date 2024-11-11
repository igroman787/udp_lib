from nacl.signing import SigningKey
from time import sleep

from udp_lib import UdpSocket
from utils_lib import parse_udp_url


peer_url = "xeh/AAABWBv3JUT9fMCQKhnZ0VRE08td02GUnOLeOZTMukLz0iugWXQYrG0=" # localhost
addr, pubkey = parse_udp_url(peer_url)
local_priv = SigningKey.generate().encode()
udp = UdpSocket(local_priv, 7001)
peer = udp.connect(addr, pubkey)

while True:
	sleep(3)
	print("last ping", peer.get_milli_ping_ago(), "ms ago")
#end while

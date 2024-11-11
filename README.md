# udp_lib
library for fast creation of UDP socket with built-in encryption (ed25519)

## server example
```python3
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
```

## client example
```python3
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
```

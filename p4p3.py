# Note: This is how I did it. It's just one way, there are multiple ways on doing this.

import socket
import threading
import os
import ssl
import base64
from time import sleep
from cryptography.fernet import Fernet
import json
import struct
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Function to encrypt a message using the public key
def encrypt_message(message, session_key):
    # Encrypt message
    f = Fernet(session_key)
    encoded_encrypted_message = f.encrypt(message)

    return encoded_encrypted_message


# Function to decrypt a message using the private key
def decrypt_message(encrypted_message, session_key):
    f = Fernet(session_key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message

def AddNodetoJson(node_name, public_key, port):
    with open("servers.json", "r") as file:
        data = json.load(file)

    data["servers"][node_name] = {"server_address": "127.0.0.1", "public_key": public_key, "port": port}

    with open("servers.json", "w") as file:
        json.dump(data, file, indent=4)

def GetClientKey(port):
    with open("servers.json", "r") as file:
        data = json.load(file)
    
    users = data["users"]

    for key, user in users.items():
        
        if int(user["port"]) == port:
            pub_bytes = bytes.fromhex(user["public_key"])
            print("pub hex=", user["public_key"])
            server_public_key = x25519.X25519PublicKey.from_public_bytes(pub_bytes)
            
            return server_public_key

    return None
def generate_key_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return private_key, public_key

priv_key, pub_key = generate_key_pair()
pub_bytes = pub_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
    )
pub_hex = pub_bytes.hex()

class Node:
    PORT_START = 9000

    def __init__(self, id, prev_node=None, next_node=None, session_key=None):
        self.id = id
        self.port = self.PORT_START + id
        self.prev_node: Node = prev_node
        self.next_node: Node = next_node
        self.session_key = session_key

# 4 bytes -  length
# 32 bytes - pubkey
# 2 bytes - nonce
# rest of the bytes - encrypted message

    def handle_client(self, conn: socket.socket, addr):
        try:
            sleep(1)  # Wait for the client to send data
            conn.settimeout(1.0)  # Set a timeout for receiving data
            tf = True
            while True:
                try:
                    data = conn.recv(4098)
                    if not data:
                        break
                    # process data
                    msg_len = struct.unpack("!I", data[0:4])
                    if len(msg_len) < 1:
                        break
                    msg = data[38:msg_len[0]]
                    client_pub_key = data[38:msg_len[0]]
                    print("msg (bytes)=", msg)
                    #print("pub=", client_pub_key.decode())
                    addr_tupl = conn.getsockname()
                    print(f"recv from {addr_tupl[1]}")
                    recv_key = GetClientKey(addr_tupl[1])
                    if recv_key == None:
                        print("no pub key")
                        return
                    shared_secret = priv_key.exchange(recv_key) 
                    print("shared= ", shared_secret)
                    info = b'tor-client-layer-encryption'
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=b'tor-encryption-protocol',
                        info=info
                    ).derive(shared_secret)
                    aesgcm = AESGCM(derived_key)
                    print("got derived key")
                    nonce = 1
                    nonce = nonce.to_bytes(12, "big")
                    txt = aesgcm.decrypt(nonce, msg, None)
                    print("msg= ", txt)
                except socket.timeout:
                    break
                except Exception as e:
                    print(f"Node {self.id} Error during receiving: {e}")
                    break

            if nodeNum > 0:
                pass
            # Send it to the next node
            else:
                # Decrypt the data

                # Create a SSL Socket
                dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

                # Get the final host from the HTTP Header
                address = self.extract_host(decrypted_data)

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as dest_socket:
                    with context.wrap_socket(
                        dest_socket, server_hostname=address
                    ) as ssock:
                        # Connect to the final host
                        ssock.connect((address, 443))
                        # Send the decrypted data to the final host
                        ssock.sendall(decrypted_data)
                        # Receive the response from the final host
                        response = ssock.recv(4096)
                        # Encrypt the response

                        # Send the encrypted response to the previous node
                        self.send_data(encrypted_response, conn)

        except Exception as e:
            print(f"Node {self.id} Error: {e}")
        finally:
            conn.close()

    # This function extracts the host from the HTTP Header
    def extract_host(self, request_bytes):
        request_str = request_bytes.decode("utf-8")  # Decode the bytes to a string
        lines = request_str.split("\r\n")  # Split the request into lines
        for line in lines:
            if line.startswith("Host: "):
                host = line.split(" ")[1]  # Extract the host part
                return host
        return None

    def send_data(self, data, s=None):
        # Send data to the node. In my implementation, s is a socket, the same from which the data was received. If it's sending to a new socket, s should be None and a new socket should be created.
        pass

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", self.port))
            s.listen()
            print(f"Node {self.id} listening on port {self.port}")
            while True:
                conn, addr = s.accept()
                print("start")
                client_thread = threading.Thread(
                    target=self.handle_client, args=(conn, addr)
                )
                client_thread.start()

node = Node(0, None, None, priv_key)
AddNodetoJson("server0", pub_hex, node.port)
node.start()

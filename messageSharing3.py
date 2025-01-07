import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import pickle
import time
from SecureRSA import SecureRSA

class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        
        # Initialize RSA
        self.rsa = SecureRSA()
        self.rsa.generate_keys(2048)
        
        # Network settings
        self.PORT = 12345
        self.server_socket = None
        self.peer_public_keys = {}  # Store peer public keys
        self.server_ready = False  # Flag to indicate server is ready
        
        # GUI Components
        self.setup_gui()
        
        # Start server
        self.start_server()
        
        # Wait for server to be ready
        while not self.server_ready:
            time.sleep(0.1)
            self.root.update()

    def setup_gui(self):
        # IP Address Frame
        ip_frame = ttk.Frame(self.root)
        ip_frame.pack(padx=5, pady=5, fill=tk.X)
        
        ttk.Label(ip_frame, text="Receiver IP:").pack(side=tk.LEFT)
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Message History
        self.history = scrolledtext.ScrolledText(self.root, height=20)
        self.history.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        
        # Message Entry Frame
        msg_frame = ttk.Frame(self.root)
        msg_frame.pack(padx=5, pady=5, fill=tk.X)
        
        self.msg_entry = ttk.Entry(msg_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Button(msg_frame, text="Send", command=self.send_message).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(msg_frame, text="Test Connection", command=self.test_connection).pack(side=tk.RIGHT, padx=5)
        
        # Bind enter key to send message
        self.msg_entry.bind('<Return>', lambda e: self.send_message())

    def get_local_ip(self):
        """Get the local IP address that can be used for network communication"""
        try:
            # Create a temporary socket to connect to an external address
            temp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_socket.connect(("8.8.8.8", 80))  # Google's DNS server
            local_ip = temp_socket.getsockname()[0]
            temp_socket.close()
            return local_ip
        except Exception:
            # Fallback method if the above fails
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                if not local_ip.startswith("127."):
                    return local_ip
            except:
                pass
            return "127.0.0.1"

    def start_server(self):
        """Start server to receive messages"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Try to bind to the port
            attempts = 0
            while attempts < 5:
                try:
                    self.history.insert(tk.END, f"Attempting to bind to port {self.PORT}...\n")
                    self.server_socket.bind(('0.0.0.0', self.PORT))
                    self.history.insert(tk.END, f"Successfully bound to port {self.PORT}\n")
                    break
                except OSError as e:
                    attempts += 1
                    self.history.insert(tk.END, f"Bind attempt {attempts} failed: {str(e)}\n")
                    time.sleep(1)
                    if attempts == 5:
                        raise Exception("Could not bind to port after 5 attempts")

            self.server_socket.listen(5)
            
            # Log local IP
            local_ip = self.get_local_ip()
            self.history.insert(tk.END, f"Your IP address: {local_ip}\n")
            self.history.insert(tk.END, f"Server listening on port {self.PORT}\n")
            
            # Start listening thread
            self.server_ready = True
            threading.Thread(target=self.listen_for_connections, daemon=True).start()
            
        except Exception as e:
            self.history.insert(tk.END, f"Failed to start server: {str(e)}\n")
            raise

    def listen_for_connections(self):
        """Listen for incoming connections"""
        self.history.insert(tk.END, "Started listening for connections...\n")
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                client_socket.settimeout(10)  # Set timeout for operations
                threading.Thread(target=self.handle_client, 
                               args=(client_socket, address),
                               daemon=True).start()
            except Exception as e:
                print(f"Connection error: {e}")

    def handle_client(self, client_socket, address):
        """Handle incoming messages from a client"""
        try:
            data = client_socket.recv(4096)
            if data:
                message_data = pickle.loads(data)
                
                if message_data.get('type') == 'public_key':
                    # Store the peer's public key
                    self.peer_public_keys[address[0]] = {
                        'e': message_data['e'],
                        'n': message_data['n']
                    }
                    # Send our public key in response
                    response = {
                        'type': 'public_key',
                        'e': self.rsa.get_public_key(),
                        'n': self.rsa.get_modulus()
                    }
                    client_socket.send(pickle.dumps(response))
                    
                elif message_data.get('type') == 'message':
                    encrypted_message = message_data['content']
                    decrypted_message = self.rsa.decrypt(encrypted_message)
                    self.history.insert(tk.END, f"{address[0]}: {decrypted_message}\n")
                    self.history.see(tk.END)
                    
                elif message_data.get('type') == 'test':
                    self.history.insert(tk.END, f"Received test message from {address[0]}: {message_data['content']}\n")
                    self.history.see(tk.END)
                    
                # Acknowledge receipt
                client_socket.send(pickle.dumps({'type': 'ack'}))
        
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def get_peer_public_key(self, ip):
        """Get public key from peer if we don't have it"""
        if ip not in self.peer_public_keys:
            try:
                # Connect to peer
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)  # Add timeout to prevent hanging
                
                # Try to connect with multiple attempts
                max_attempts = 3
                for attempt in range(max_attempts):
                    try:
                        sock.connect((ip, self.PORT))
                        break
                    except socket.error as e:
                        if attempt == max_attempts - 1:  # Last attempt
                            raise e
                        time.sleep(1)  # Wait before retrying
                
                # Send our public key
                key_data = {
                    'type': 'public_key',
                    'e': self.rsa.get_public_key(),
                    'n': self.rsa.get_modulus()
                }
                sock.send(pickle.dumps(key_data))
                
                # Receive their public key
                response = sock.recv(4096)
                if response:
                    key_data = pickle.loads(response)
                    if key_data.get('type') == 'public_key':
                        self.peer_public_keys[ip] = {
                            'e': key_data['e'],
                            'n': key_data['n']
                        }
                        return True
                
            except Exception as e:
                print(f"Error getting peer public key: {e}")
                self.history.insert(tk.END, f"Connection error: {str(e)}\n")
                return False
            finally:
                sock.close()
        return True

    def send_message(self):
        """Send message to peer"""
        message = self.msg_entry.get().strip()
        if not message:
            return
            
        ip = self.ip_entry.get().strip()
        if not ip:
            self.history.insert(tk.END, "Please enter receiver's IP address\n")
            return
            
        # Get peer's public key if we don't have it
        if not self.get_peer_public_key(ip):
            self.history.insert(tk.END, "Failed to get receiver's public key\n")
            return
            
        try:
            # Create temporary RSA instance with peer's public key
            temp_rsa = SecureRSA()
            temp_rsa.rsa.e = self.peer_public_keys[ip]['e']
            temp_rsa.rsa.n = self.peer_public_keys[ip]['n']
            
            # Encrypt and send message
            encrypted_message = temp_rsa.encrypt(message)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # Add timeout
            sock.connect((ip, self.PORT))
            
            message_data = {
                'type': 'message',
                'content': encrypted_message
            }
            sock.send(pickle.dumps(message_data))
            
            # Wait for acknowledgment
            response = sock.recv(4096)
            if response:
                response_data = pickle.loads(response)
                if response_data.get('type') == 'ack':
                    # Update history
                    self.history.insert(tk.END, f"You: {message}\n")
                    self.history.see(tk.END)
                    
                    # Clear message entry
                    self.msg_entry.delete(0, tk.END)
            
        except Exception as e:
            self.history.insert(tk.END, f"Failed to send message: {str(e)}\n")
        finally:
            sock.close()
            
    def test_connection(self):
        """Test connection to receiver without encryption"""
        ip = self.ip_entry.get().strip()
        if not ip:
            self.history.insert(tk.END, "Please enter receiver's IP address\n")
            return
            
        try:
            # Create test socket
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            
            self.history.insert(tk.END, f"Local machine info:\n")
            self.history.insert(tk.END, f"- Using port: {self.PORT}\n")
            self.history.insert(tk.END, f"- Local IP: {self.get_local_ip()}\n")
            self.history.insert(tk.END, f"\nAttempting to connect to {ip}:{self.PORT}...\n")
            
            test_socket.connect((ip, self.PORT))
            
            # Send simple test message
            test_message = pickle.dumps({
                'type': 'test',
                'content': 'Test message from sender'
            })
            test_socket.send(test_message)
            
            self.history.insert(tk.END, "Test message sent successfully!\n")
            
        except ConnectionRefusedError:
            self.history.insert(tk.END, f"Connection refused - Is the receiver running and listening?\n")
        except socket.timeout:
            self.history.insert(tk.END, f"Connection timed out - Check IP and port\n")
        except Exception as e:
            self.history.insert(tk.END, f"Test failed: {str(e)}\n")
        finally:
            test_socket.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
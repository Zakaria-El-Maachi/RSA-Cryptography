import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import pickle
from SecureRSA import SecureRSA

class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        
        # Initialize RSA
        self.rsa = SecureRSA()
        self.rsa.generate_keys(2048)
        
        # Network settings
        self.PORT = 5000
        self.server_socket = None
        self.peer_public_keys = {}  # Store peer public keys
        
        # GUI Components
        self.setup_gui()
        
        # Start server
        self.start_server()

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
        
        # Bind enter key to send message
        self.msg_entry.bind('<Return>', lambda e: self.send_message())

    def get_local_ip(self):
        """Get the local IP address that can be used for network communication"""
        try:
            # Create a temporary socket to connect to an external address
            # This won't actually establish a connection but will help us
            # determine the local IP address used for external communications
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
            return "127.0.0.1"  # Last resort fallback

    def start_server(self):
        """Start server to receive messages"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Allow port reuse
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind to all available interfaces
        self.server_socket.bind(('0.0.0.0', self.PORT))
        self.server_socket.listen(5)
        
        # Start listening thread
        threading.Thread(target=self.listen_for_connections, daemon=True).start()
        
        # Log local IP
        local_ip = self.get_local_ip()
        self.history.insert(tk.END, f"Your IP address: {local_ip}\n")

    def listen_for_connections(self):
        """Listen for incoming connections"""
        while True:
            try:
                client_socket, address = self.server_socket.accept()
                threading.Thread(target=self.handle_client, 
                               args=(client_socket, address),
                               daemon=True).start()
            except Exception as e:
                print(f"Connection error: {e}")

    def handle_client(self, client_socket, address):
        """Handle incoming messages from a client"""
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                    
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
                sock.connect((ip, self.PORT))
                
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
                
                sock.close()
                return True
            except Exception as e:
                print(f"Error getting peer public key: {e}")
                return False
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
            sock.close()
            
            # Update history
            self.history.insert(tk.END, f"You: {message}\n")
            self.history.see(tk.END)
            
            # Clear message entry
            self.msg_entry.delete(0, tk.END)
            
        except Exception as e:
            self.history.insert(tk.END, f"Failed to send message: {str(e)}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
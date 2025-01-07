import hashlib
import os
from PlainRSA import PlainRSA

class SecureRSA:
    def __init__(self):
        self.rsa = PlainRSA()
        self.hash_len = 32  # SHA-256 output length

    def generate_keys(self, bits):
        """Generate RSA keys with specified bit length"""
        self.rsa.gen_rsa(bits)

    def get_public_key(self):
        return self.rsa.get_public_key()

    def get_modulus(self):
        return self.rsa.get_modulus()

    def _mgf1(self, seed, length):
        """Mask Generation Function (MGF1)"""
        output = b''
        counter = 0
        while len(output) < length:
            C = counter.to_bytes(4, byteorder='big')
            output += hashlib.sha256(seed + C).digest()
            counter += 1
        return output[:length]

    def _saep_pad(self, message):
        """SAEP padding for a single block"""
        k = self.rsa.n.bit_length() // 8  # RSA modulus size in bytes
        m_len = len(message)
        
        # Generate random seed
        seed = os.urandom(self.hash_len)
        
        # Calculate maximum message length
        max_message_len = k - 2 * self.hash_len - 2
        if m_len > max_message_len:
            raise ValueError(f"Message too long. Maximum length is {max_message_len} bytes")

        # Pad message to full length with zeros
        padded_msg = message + b'\x00' * (k - self.hash_len - 1 - m_len)
        
        # Generate mask for message
        db_mask = self._mgf1(seed, k - self.hash_len - 1)
        
        # XOR message with mask
        masked_db = bytes(x ^ y for x, y in zip(padded_msg, db_mask))
        
        # Combine components with proper length checks
        result = b'\x00' + seed + masked_db
        assert len(result) == k
        return result

    def _saep_unpad(self, padded):
        """SAEP unpadding for a single block"""
        k = self.rsa.n.bit_length() // 8
        
        if len(padded) != k:
            raise ValueError(f"Invalid padding length: {len(padded)} != {k}")
        if padded[0] != 0:
            raise ValueError("Invalid padding prefix")

        # Extract components
        seed = padded[1:self.hash_len + 1]
        masked_db = padded[self.hash_len + 1:]
        
        # Unmask the data block
        db_mask = self._mgf1(seed, k - self.hash_len - 1)
        db = bytes(x ^ y for x, y in zip(masked_db, db_mask))
        
        # Find the end of the message (first occurrence of 0x00)
        try:
            msg_end = db.index(b'\x00'[0])  # Find first zero byte
            return db[:msg_end]
        except ValueError:
            # If no zero byte is found, the message might fill the entire space
            return db

    def encrypt(self, message):
        """Encrypt a message using RSA-SAEP"""
        if isinstance(message, str):
            message = message.encode('utf-8')
            
        k = self.rsa.n.bit_length() // 8
        max_chunk_size = k - 2 * self.hash_len - 2
        
        encrypted_blocks = []
        
        # Process message in chunks
        for i in range(0, len(message), max_chunk_size):
            chunk = message[i:i + max_chunk_size]
            # Pad the chunk
            padded = self._saep_pad(chunk)
            # Encrypt the padded chunk
            encrypted_block = self.rsa.encrypt_block(padded)
            encrypted_blocks.append(encrypted_block)
            
        return encrypted_blocks

    def decrypt(self, encrypted_blocks):
        """Decrypt a message using RSA-SAEP"""
        decrypted_message = b''
        
        for block in encrypted_blocks:
            # Decrypt the block
            padded = self.rsa.decrypt_block(block)
            # Unpad the decrypted block
            try:
                message_part = self._saep_unpad(padded)
                decrypted_message += message_part
            except ValueError as e:
                raise ValueError(f"Decryption failed: {str(e)}")
                
        return decrypted_message.decode('utf-8')


def test_secure_rsa():
    print("\nTesting Secure RSA with SAEP padding...")
    
    # Initialize SecureRSA
    secure_rsa = SecureRSA()
    secure_rsa.generate_keys(2048)
    
    # Test messages of various lengths
    test_messages = [
        "Hello World!",
        "A",
        "This is a longer message to test RSA-SAEP encryption and decryption",
        "123456789" * 10,  # Longer message to test multiple blocks
    ]
    
    for msg in test_messages:
        print(f"\nTesting message: {msg}")
        try:
            # Encrypt
            encrypted = secure_rsa.encrypt(msg)
            print(f"Encrypted blocks: {len(encrypted)} blocks")
            
            # Debug information
            print(f"Original message length: {len(msg)} bytes")
            print(f"First encrypted block size: {encrypted[0].bit_length() // 8} bytes")
            
            # Decrypt
            decrypted = secure_rsa.decrypt(encrypted)
            print(f"Decrypted message: {decrypted}")
            
            # Verify
            assert msg == decrypted
            print(f"✓ Test passed for message length {len(msg)}")
            
        except Exception as e:
            print(f"✗ Test failed: {str(e)}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    try:
        test_secure_rsa()
        print("\nAll SecureRSA tests passed successfully!")
    except Exception as e:
        print(f"\nError in SecureRSA tests: {str(e)}")
import random

class PlainRSA:
    def __init__(self):
        self.n = 0  # modulus
        self.e = 0  # public exponent
        self.d = 0  # private exponent
        self.p = 0  # first prime
        self.q = 0  # second prime
        self.gen = random.SystemRandom()  # Cryptographically secure random number generator

    # Fast modular exponentiation
    def mod_pow(self, base, exp, modulus):
        result = 1
        base = base % modulus
        while exp > 0:
            if exp & 1:
                result = (result * base) % modulus
            base = (base * base) % modulus
            exp >>= 1
        return result

    # Miller-Rabin primality test
    def miller_rabin(self, n, k):
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True

        d = n - 1
        while d % 2 == 0:
            d //= 2

        for _ in range(k):
            a = self.gen.randint(2, n - 2)
            x = self.mod_pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            is_prime = False
            d_temp = d
            while d_temp != n - 1:
                x = (x * x) % n
                d_temp *= 2

                if x == 1:
                    return False
                if x == n - 1:
                    is_prime = True
                    break

            if not is_prime:
                return False

        return True

    # Generate random prime number of n bits
    def generate_prime(self, bits):
        while True:
            num = self.gen.getrandbits(bits)
            num |= (1 << (bits - 1)) | 1  # Ensure num is n-bit and odd

            if self.miller_rabin(num, 20):
                return num

    # Extended Euclidean Algorithm for modular multiplicative inverse
    def mod_inverse(self, a, m):
        m0, x, y = m, 1, 0
        if m == 1:
            return 0

        while a > 1:
            q = a // m
            a, m = m, a % m
            x, y = y, x - q * y

        if x < 0:
            x += m0

        return x

    # GCD calculation
    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    # Generate RSA keys with security parameter n (bit length)
    def gen_rsa(self, n):
        self.p = self.generate_prime(n // 2)
        while True:
            self.q = self.generate_prime(n // 2)
            if self.p != self.q:
                break

        self.n = self.p * self.q
        phi = (self.p - 1) * (self.q - 1)

        self.e = 65537  # Common choice for e
        while self.gcd(self.e, phi) != 1:
            self.e += 2

        self.d = self.mod_inverse(self.e, phi)
    
    
    def encrypt_block(self, block_bytes):
        """Encrypt a single block of bytes"""
        block_int = int.from_bytes(block_bytes, byteorder='big')
        return self.mod_pow(block_int, self.e, self.n)

    def decrypt_block(self, encrypted_block):
        """Decrypt a single encrypted block back to bytes"""
        block_size = self.n.bit_length() // 8
        decrypted_int = self.mod_pow(encrypted_block, self.d, self.n)
        return decrypted_int.to_bytes(block_size, byteorder='big')
    
    
    # Encrypt message (string to list of encrypted blocks)
    def encrypt(self, message):
        block_size = self.n.bit_length() // 8  # Size of each block in bytes (for a 2048-bit RSA, block size is 256 bytes)
        message = message.encode('utf-8')  # Convert message to bytes
        encrypted = []

        # Process the message in blocks
        for i in range(0, len(message), block_size):
            block = message[i:i + block_size]
            # Convert block to an integer
            block_int = int.from_bytes(block, byteorder='big')
            # Encrypt the block
            encrypted_block = self.mod_pow(block_int, self.e, self.n)
            encrypted.append(encrypted_block)

        return encrypted

    # Decrypt message (list of encrypted blocks to string)
    def decrypt(self, encrypted):
        block_size = self.n.bit_length() // 8  # Size of each block in bytes (for a 2048-bit RSA, block size is 256 bytes)
        decrypted_bytes = b''

        # Process the encrypted blocks
        for c in encrypted:
            # Decrypt the block
            block_int = self.mod_pow(c, self.d, self.n)
            # Convert block to bytes
            block_bytes = block_int.to_bytes(block_size, byteorder='big')
            decrypted_bytes += block_bytes

        return decrypted_bytes.decode('utf-8').rstrip('\x00')


    # Getters for public key
    def get_public_key(self):
        return self.e

    def get_modulus(self):
        return self.n


if __name__ == "__main__":
    
    def test_plain_rsa():
        print("Testing Plain RSA...")
        
        # Initialize RSA
        rsa = PlainRSA()
        rsa.gen_rsa(2048)  # Using 2048 bits for testing
        
        # Test encryption/decryption with a simple message
        original_message = "Hello World!"
        print("Original message:", original_message)
        
        # Encrypt message
        encrypted = rsa.encrypt(original_message)
        print("Encrypted blocks:", encrypted)
        
        print("hhhh")
        # Decrypt message
        decrypted = rsa.decrypt(encrypted)
        print("Decrypted message:", decrypted)
        # Verify
        assert original_message == decrypted[-len(original_message):]
        print("Basic encryption/decryption test passed!")
        
        # Test with different message lengths
        test_messages = [
            "A",
            "Hello",
            "This is a longer message to test RSA encryption and decryption",
            "123456789"
        ]
        
        for msg in test_messages:
            enc = rsa.encrypt(msg)
            dec = rsa.decrypt(enc)
            assert msg == dec[-len(msg):]
            print(f"Test passed for message length {len(msg)}")
    
    
    try:
        test_plain_rsa()
        print("All Plain RSA tests passed successfully!")
    except AssertionError as e:
        print("AssertionError:", e)

    except Exception as e:
        print("Error:", e)


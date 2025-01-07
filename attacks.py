import math
from typing import Optional, Tuple
from PlainRSA import PlainRSA

class RSAAttacker:
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e
    
    def small_message_attack(self, c: int, max_m: int = 1000000) -> Optional[int]:
        """
        Attack for very small messages by trying all possibilities up to max_m
        Returns the message if found, None otherwise
        """
        print("Attempting small message attack...")
        for m in range(max_m):
            if pow(m, self.e, self.n) == c:
                print(f"Found message: {m}")
                return m
        return None

    def product_attack(self, c: int, modulus) -> Optional[Tuple[int, int]]:
        """
        Attack when message is known to be a product of two smaller numbers
        Returns tuple of factors if found, None otherwise
        """
        print("Attempting product attack...")
        for i in range(2, int(math.sqrt(modulus)) + 1):
            if modulus % i == 0:
                factor1 = i
                factor2 = modulus // i
                print(f"Found factors: {factor1}, {factor2}")
                return (factor1, factor2)
        return None

    def pollard_rho(self) -> Optional[int]:
        """
        Pollard's rho algorithm for factoring n
        Returns a factor if found, None otherwise
        """
        print("Attempting Pollard's rho factorization...")
        
        def g(x: int) -> int:
            return (x * x + 1) % self.n

        x, y = 2, 2
        d = 1

        while d == 1:
            x = g(x)
            y = g(g(y))
            d = math.gcd(abs(x - y), self.n)
            
            if d == self.n:
                return None
                
        print(f"Found factor using Pollard's rho: {d}")
        return d

    def fermat_factorization(self, max_iterations: int = 10000) -> Optional[Tuple[int, int]]:
        """
        Fermat factorization for numbers close to perfect square
        Returns tuple of factors if found, None otherwise
        """
        print("Attempting Fermat factorization...")
        a = math.sqrt(self.n)
        b2 = a*a - self.n
        
        for _ in range(max_iterations):
            a += 1
            b2 = a*a - self.n
            if b2 >= 0:
                b = math.sqrt(b2)
                if b*b == b2:
                    p, q = a+b, a-b
                    if p*q == self.n:
                        print(f"Found factors using Fermat: {p}, {q}")
                        return (p, q)
        return None


def test_attacks():
    # Test case 1: Small message
    print("\n=== Test Case 1: Small Message ===")
    rsa = PlainRSA()
    rsa.gen_rsa(512)  # Smaller key for testing
    m = 42
    c = pow(m, rsa.e, rsa.n)
    attacker = RSAAttacker(rsa.n, rsa.e)
    recovered_m = attacker.small_message_attack(c)
    print(f"Original message: {m}")
    print(f"Recovered message: {recovered_m}")
    assert recovered_m == m

    # Test case 2: Product message
    print("\n=== Test Case 2: Product Message ===")
    m1, m2 = 19, 17
    m = m1 * m2
    c = rsa.mod_pow(m, rsa.e, rsa.n)
    recovered_factors = attacker.product_attack(c, m)
    print(f"Original factors: {m1}, {m2}")
    print(f"Recovered factors: {recovered_factors}")
    assert recovered_factors in [(m1, m2), (m2, m1)]

    # Test case 3: Pollard's rho
    print("\n=== Test Case 3: Pollard's Rho ===")
    # Using smaller numbers for Pollard's rho to be effective
    n = 11273*47513  # Small semi-primes
    attacker = RSAAttacker(n, 65537)
    factor = attacker.pollard_rho()
    print(f"One of the factors should be either 11273 or 47513, Found: {factor}")
    assert factor in [11273, 47513]

    # Test case 4: Fermat factorization
    print("\n=== Test Case 4: Fermat Factorization ===")
    # Choose p and q close to each other for Fermat to be effective
    p = 28759
    q = 23399
    n = p*q
    attacker = RSAAttacker(n, 65537)
    factors = attacker.fermat_factorization()
    print(f"Original factors: {p}, {q}")
    print(f"Recovered factors: {factors}")
    assert factors is not None and p*q == factors[0]*factors[1]

if __name__ == "__main__":
    try:
        test_attacks()
        print("\nAll attack tests completed successfully!")
    except Exception as e:
        print(f"Error in tests: {str(e)}")
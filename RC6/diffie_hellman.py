import random
from math import isqrt
from typing import Set

class DiffieHellman:
    def get_p(self, bits=128):
        while True:
            p = random.getrandbits(bits)
            if self.is_prime(p):
                return p

    def is_prime(self, n, k=10):
        """Test Miller-Rabin"""
        if n <= 1 or n == 4:
            return False
        if n <= 3:
            return True
        d = n - 1
        while d % 2 == 0:
            d //= 2
        for _ in range(k):
            a = random.randint(2, n - 2)
            if not self.miller_test(d, n, a):
                return False
        return True

    def miller_test(self, d, n, a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        while d != n - 1:
            x = (x * x) % n
            d *= 2
            if x == 1:
                return False
            if x == n - 1:
                return True
        return False

    def prime_factors(self, n: int) -> Set[int]:
        factors = set()
        while n % 2 == 0:
            factors.add(2)
            n //= 2
        for i in range(3, isqrt(n) + 1, 2):
            while n % i == 0:
                factors.add(i)
                n //= i
        if n > 2:
            factors.add(n)
        return factors

    def get_g(self, p: int) -> int:
        phi = p - 1
        prime_factors = self.prime_factors(phi)
        for g in range(2, phi):
            flag = False
            for factor in prime_factors:
                if pow(g, phi // factor, p) == 1:
                    flag = True
                    break
            if not flag:
                return g
        return -1

    def power_mod(self, a: int, b: int, n: int) -> int:
        return pow(a, b, n) 

    def pad_left_zeros(self, string: str, length: int) -> str:
        return string.zfill(length)

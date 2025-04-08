from diffie_hellman import DiffieHellman
import random

dh = DiffieHellman()

# Generare p si g
p = dh.get_p(bits=64)  
g = dh.get_g(p)

print(f"Valori globale:")
print(f"p = {p}")
print(f"g = {g}")

# Cheie privata aleatorie pentru Alice si Bob
a = random.randint(2, p - 2)
b = random.randint(2, p - 2)

# Chei publice
A = pow(g, a, p)
B = pow(g, b, p)

print(f"\nAlice -> a = {a}, A = {A}")
print(f"Bob   -> b = {b}, B = {B}")

# Cheie secreta calculata de ambele parti
secret_alice = pow(B, a, p)
secret_bob   = pow(A, b, p)

print(f"\nSecret comun Alice: {secret_alice}")
print(f"Secret comun Bob  : {secret_bob}")
print(f"\nMatch: {' DA' if secret_alice == secret_bob else 'NU'}")

from typing import List 
WORD_MASK = 0xFFFFFFFF  # Masca pentru a pastra valorile pe 32 de biti (4294967295)

class RC6:
    def __init__(self):
        self.w = 32  # dimensiunea unui cuvant in biti
        self.r = 20  # nr de runde de criptare/decriptare
        self.lgw = 5  # pentru shiftare / rotatie
        self.P32 = 0xB7E15163  # constanta
        self.Q32 = 0x9E3779B9  # constanta folosita la generarea cheilor

    def _rotate_left(self, val, n):
        n %= 32  # rotirea intre 0 si 31 de biti
        return ((val << n) | (val >> (32 - n))) & WORD_MASK  

    def _rotate_right(self, val, n):
        n %= 32  
        return ((val >> n) | (val << (32 - n))) & WORD_MASK

    def _multiply_unsigned(self, a, b):
        return (a * b) & WORD_MASK  

    def key_schedule(self, L: List[int], c: int, r: int) -> List[int]:
        S = [0] * (2 * r + 4)  # initializare cheia extinsa S cu 2r+4 elemente
        S[0] = self.P32  # primul element e P32
        for k in range(1, 2 * r + 4):
            S[k] = (S[k - 1] + self.Q32) & WORD_MASK  # fiecare element urmator = anterior + Q32

        A = B = 0  # registrii temporari A si B
        i = j = 0  # index pentru S si L
        v = 3 * max(c, 2 * r + 4)  # nr total de iteratii de mixare

        for _ in range(v):
            A = self._rotate_left((S[i] + A + B) & WORD_MASK, 3)  
            S[i] = A
            shift_amount = (A + B) % 32  
            B = self._rotate_left((L[j] + A + B) & WORD_MASK, shift_amount)  
            L[j] = B
            i = (i + 1) % (2 * r + 4)  # increment circular
            j = (j + 1) % c  # increment circular pentru cheia L

        return S  # se returneaza cheia extinsa
    
    def encrypt_unsigned_integer(self, input: List[int], S: List[int], r: int) -> List[int]:
        A, B, C, D = input  # impartire bloc de 128 biti in patru cuvinte de cate 32 biti
        B = (B + S[0]) & WORD_MASK  # adaugare subcheie la B
        D = (D + S[1]) & WORD_MASK  # adaugare subcheie la D

        for i in range(1, r + 1):  # runde RC6
            t = self._rotate_left(self._multiply_unsigned(B, (2 * B + 1) & WORD_MASK), 5)  
            u = self._rotate_left(self._multiply_unsigned(D, (2 * D + 1) & WORD_MASK), 5)  
            shift_u = u % 32  # shift pentru A
            shift_t = t % 32  # shift pentru C
            A = (self._rotate_left(A ^ t, shift_u) + S[2 * i]) & WORD_MASK 
            C = (self._rotate_left(C ^ u, shift_t) + S[2 * i + 1]) & WORD_MASK  
            A, B, C, D = B, C, D, A  # rotire registrii circular

        A = (A + S[2 * r + 2]) & WORD_MASK  # adaugare ultimele subchei
        C = (C + S[2 * r + 3]) & WORD_MASK

        return [A, B, C, D]  

    def decrypt_unsigned_integer(self, input: List[int], S: List[int], r: int) -> List[int]:
        A, B, C, D = input  # despachetare bloc criptat
        C = (C - S[2 * r + 3]) & WORD_MASK  # scoatem ultimele subchei
        A = (A - S[2 * r + 2]) & WORD_MASK

        for i in range(r, 0, -1):  # inversare rotire
            A, B, C, D = D, A, B, C  # invers rotire registrii
            u = self._rotate_left(self._multiply_unsigned(D, (2 * D + 1) & WORD_MASK), 5) 
            t = self._rotate_left(self._multiply_unsigned(B, (2 * B + 1) & WORD_MASK), 5)  
            shift_t = t % 32
            shift_u = u % 32
            C = self._rotate_right((C - S[2 * i + 1]) & WORD_MASK, shift_t) ^ u  # decriptare C
            A = self._rotate_right((A - S[2 * i]) & WORD_MASK,  shift_u ) ^ t  # decriptare A

        D = (D - S[1]) & WORD_MASK  # scoatere primele subchei
        B = (B - S[0]) & WORD_MASK

        return [A, B, C, D]  

    def convert_unsigned_integer_array_to_string(self, array: List[int]) -> str:
        return ' '.join(str(num) for num in array)  # convertire lista de numere in sir text cu spații

    def convert_string_to_unsigned_integer_array(self, input_str: str) -> List[int]:
        return [int(s) for s in input_str.strip().split() if s]  # extragere numere intregi dintr-un sir

    def encrypt_block(self, input_block: List[int], S: List[int], r: int) -> str:
        out = self.encrypt_unsigned_integer(input_block, S, r)  # criptare bloc de 4 intregi
        return self.convert_unsigned_integer_array_to_string(out)  # convertire la string

    def decrypt_block(self, input_block: List[int], S: List[int], r: int) -> List[int]:
        return self.decrypt_unsigned_integer(input_block, S, r)  # decriptare bloc de 4 intregi

    def encrypt(self, plaintext: str, S: List[int], r: int) -> str:
        data = plaintext.encode()  # convertire text in bytes
        pad_len = (4 - len(data) % 4) % 4  # completare la multiplu de 4
        data += b'\x00' * pad_len  # adaugare padding cu 0

        blocks = [list(data[i:i+4]) for i in range(0, len(data), 4)]  # impartire in blocuri de 4 bytes
        result = []
        for block in blocks:
            while len(block) < 4:
                block.append(0)  # completare blocuri care nu au 4 elemente
            result.append(self.encrypt_block(block, S, r))  

        return ' '.join(result)  

    def decrypt(self, input_str: str, S: List[int], r: int) -> str:
        values = self.convert_string_to_unsigned_integer_array(input_str)  
        result_bytes = []
        for i in range(0, len(values), 4):
            block = values[i:i+4]
            dec_block = self.decrypt_block(block, S, r)  
            result_bytes.extend(b & 0xFF for b in dec_block)  # se iau doar ultimii 8 biti per int

        return self.remove_zero_padding(bytes(result_bytes).decode(errors='ignore'))  # transformare in string

    def remove_zero_padding(self, input_str: str) -> str:
        return input_str.rstrip('\x00')  # eliminare padding de 0 de la final

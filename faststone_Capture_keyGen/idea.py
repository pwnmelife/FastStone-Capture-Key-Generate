
class IDEA_Encryption:
    def __init__(self, key):
        self.key = key
        
        pass

    def add_mod(self, a, b):
        return (a + b) % 0x10000

    def mul_mod(self, a, b):
        tmp_a = (1 << 16) if a == 0 else a
        tmp_b = (1 << 16) if b == 0 else b
        return (tmp_a * tmp_b) % 0x10001

    def rotate_left(self, subKey):
        highPart = subKey[0] >> (16 - 5)
        for i in range(7):
            subKey[i] = ((subKey[i] << 5) | (subKey[i + 1] >> (16 - 5))) & 0xffff
        
        subKey[7] = ((subKey[7] << 5) | highPart) & 0xffff
        return subKey

    def round(self, data, round):
        out = []
        tmp = data.copy()
        
        tmp[0] = self.mul_mod(data[0], self.subKey[6 * round])
        tmp[1] = self.add_mod(data[1], self.subKey[6 * round + 1])
        tmp[2] = self.add_mod(data[2], self.subKey[6 * round + 2])
        tmp[3] = self.mul_mod(data[3], self.subKey[6 * round + 3])

        out.append(tmp[0] ^ tmp[2])
        out.append(tmp[1] ^ tmp[3])

        out.append(self.mul_mod(out[0], self.subKey[6 * round + 4]))
        out.append(self.add_mod(out[1], out[2]))

        out.append(self.mul_mod(out[3], self.subKey[6 * round + 5]))
        out.append(self.add_mod(out[2], out[4]))
        
        out[0] = tmp[0] ^ out[4]
        out[1] = tmp[1] ^ out[5]

        out[2] = tmp[2] ^ out[4]
        out[3] = tmp[3] ^ out[5]

        out[1], out[2] = out[2], out[1]
        
        return out[:4]

    def generate_subkey(self):
        subKey = []

        for i in range(8):
            subKey.append((self.key[i * 2] << 8) | (self.key[2 * i + 1]))
        
        i = 1
        tmpKey = subKey.copy()
        while i <= 5:
            for j in range(5):
                tmpKey = self.rotate_left(tmpKey)
            for j in range(8):
                subKey.append(tmpKey[j])
            i += 1
        
        for i in range(5):
            self.rotate_left(tmpKey)
        
        subKey.append(tmpKey[0])
        subKey.append(tmpKey[1])
        subKey.append(tmpKey[2])
        subKey.append(tmpKey[3])

        self.subKey = subKey

    def transform(self, data_encrypt):
        cipher_bytes = str()
        for s in data_encrypt:
            cipher_bytes += chr((s[0] >> 8) & 0xff)
            cipher_bytes += chr(s[0] & 0xff)
            cipher_bytes += chr((s[1] >> 8) & 0xff)
            cipher_bytes += chr(s[1] & 0xff)
            cipher_bytes += chr((s[2] >> 8) & 0xff)
            cipher_bytes += chr(s[2] & 0xff)
            cipher_bytes += chr((s[3] >> 8) & 0xff)
            cipher_bytes += chr(s[3] & 0xff)
        return cipher_bytes.encode('latin1')

    def encrypt(self, data):
        data_length = int(len(data) / 8)
        data_encrypt = []
        for i in range(data_length):
            tmp = []
            data_copy = data[i * 8: 8 * ( i + 1)]
            for j in range(4):
                tmp.append(((data_copy[j * 2] << 8) | (data_copy[2 * j + 1])) & 0xffff)
            
            for j in range(8):
                tmp = self.round(tmp,j)
            
            tmp[1], tmp[2] = tmp[2], tmp[1]

            tmp[0] = self.mul_mod(tmp[0], self.subKey[48])
            tmp[1] = self.add_mod(tmp[1], self.subKey[49])
            tmp[2] = self.add_mod(tmp[2], self.subKey[50])
            tmp[3] = self.mul_mod(tmp[3], self.subKey[51])
            data_encrypt.append(tmp)
        
        return self.transform(data_encrypt)
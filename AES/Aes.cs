using System;

/*
Authors:
Adam Stefański 242534
Bartłomiej Włodarski 242566
 */

namespace AES
{
    public class AESException : Exception
    {
        public AESException(string message) : base(message) { }
    }
    public class Aes
    {
        private int rounds;
        private byte[][] keyWords;

        private readonly byte[][] roundConst = new byte[10][] {
    new byte[4] { 0x01, 0x00, 0x00, 0x00 },
    new byte[4] { 0x02, 0x00, 0x00, 0x00 },
    new byte[4] { 0x04, 0x00, 0x00, 0x00 },
    new byte[4] { 0x08, 0x00, 0x00, 0x00 },
    new byte[4] { 0x10, 0x00, 0x00, 0x00 },
    new byte[4] { 0x20, 0x00, 0x00, 0x00 },
    new byte[4] { 0x40, 0x00, 0x00, 0x00 },
    new byte[4] { 0x80, 0x00, 0x00, 0x00 },
    new byte[4] { 0x1b, 0x00, 0x00, 0x00 },
    new byte[4] { 0x36, 0x00, 0x00, 0x00 } };

        private readonly byte[] sBox = new byte[256] {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F


        private readonly byte[] inverseSBox = new byte[256] {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, //0
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, //1
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, //2
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, //3
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, //4
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, //5
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, //6
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, //7
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, //8
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, //9
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, //A
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, //B
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, //C
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, //D
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, //E
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }; //F


        private readonly byte[] mixColumnsBox = new byte[16] {
    //0     1    2      3    
    0x02, 0x03, 0x01, 0x01, //0
    0x01, 0x02, 0x03, 0x01, //1
    0x01, 0x01, 0x02, 0x03, //2
    0x03, 0x01, 0x01, 0x02, }; //4

        private readonly byte[] mixColumnsBoxInverse = new byte[16] {
    //0     1    2      3    
    0x0E, 0x0B, 0x0D, 0x09, //0
    0x09, 0x0E, 0x0B, 0x0D, //1
    0x0D, 0x09, 0x0E, 0x0B, //2
    0x0B, 0x0D, 0x09, 0x0E, }; //4


        //Checks if the key size is correct and sets the number of rounds
        private bool CheckKey(byte[] key)
        {
            if (key.Length == 16)
                rounds = 10;
            else if (key.Length == 24)
                rounds = 12;
            else if (key.Length == 32)
                rounds = 14;
            else
                return false;
            return true;
        }

        //Generates expanded key
        private void GenerateExpandedKey(byte[] key)
        {
            if (!CheckKey(key)) throw new AESException("Wrong key size.");
            keyWords = new byte[4 * (rounds + 1)][]; //4 words per round + 4 for original key
            keyWords = KeyExpansion(key);
        }

        //Xor of two byte arrays
        private byte[] Xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) { throw new AESException("Both parameters must have equal size."); }
            byte[] result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
            {
                result[i] = (byte)(a[i] ^ b[i]);
            }
            return result;
        }

        //Substitutes word with values from sBox
        private byte[] SubWord(byte[] w)
        {
            byte[] temp = new byte[4];
            for (int i = 0; i < w.Length; i++)
            {
                temp[i] = sBox[w[i]];
            }
            return temp;
        }

        //Rotates word from {a0, a1, a2, a3} to {a1, a2, a3, a0}
        private byte[] RotWord(byte[] w)
        {
            byte[] temp = new byte[4];
            for (int i = 0; i < w.Length; i++)
            {
                temp[i] = w[(i + 1) % 4];
            }
            return temp;
        }

        //Expands key to 4 * (rounds + 1) words
        private byte[][] KeyExpansion(byte[] key)
        {
            int nk = key.Length / 4; //nk - number of 32-bit words comprising the cipher key
            byte[][] keyWords = new byte[4 * (rounds + 1)][]; //2D array of 4 * (rounds + 1) words

            //Assinging key to first 4 words
            for (int i = 0; i < nk; i++)
            {
                keyWords[i] = new byte[4] { key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3] };
            }
            //Generating rest of the extended key
            for (int i = nk; i < 4 * (rounds + 1); i++)
            {
                keyWords[i] = new byte[4];
                byte[] temp = keyWords[i - 1];
                //If position of the word is a multiple of nk
                if (i % nk == 0)
                {
                    //Using RotWord and SubWord for the prevoius word and xoring with round constant
                    temp = Xor(SubWord(RotWord(temp)), roundConst[(i / nk) - 1]);
                }
                else if (nk == 8 && i % nk == 4) //If 256-bit key (nk=8) and i-4 is a multiple of nk
                {
                    temp = SubWord(temp);
                }
                keyWords[i] = Xor(keyWords[i - nk], temp); //Xor of the [i-nk] word and previous word
            }
            return keyWords;
        }

        //Adding round key to block with xor
        private byte[] AddRoundKey(byte[] block, int round)
        {
            byte[] tempBlock = new byte[16];
            int k = 0;
            //For each word in the round key
            for (int i = 4 * round; i < 4 * round + 4; i++)
            {
                //For each byte in a word
                for (int j = 0; j < 4; j++)
                {
                    tempBlock[k] = (byte)(block[k] ^ keyWords[i][j]);
                    k++;
                }
            }
            return tempBlock;
        }

        private byte[] SubBytes(byte[] block) //SubBytes
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] = sBox[block[i]]; //assigning corresponding value from sBox
            }
            return block;
        }

        private byte[] SubBytesInverse(byte[] block) //Inverse SubBytes
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] = inverseSBox[block[i]]; //same as normal SubBytes, but with different sBox
            }
            return block;
        }

        private byte[] ShiftRows(byte[] state) //ShiftRows
        {
            byte[] shiftedRows = new byte[16];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    //(col+row) determines which column we take the byte from
                    //we have to use modulo 4, to make sure it does not go out of bounds
                    //then we offset each row by number of bytes equal to the row number (row 0 is not shifted)
                    shiftedRows[col * 4 + row] = state[4 * ((col + row) % 4) + row]; 
                }
            }


            return shiftedRows;
        }

        private byte[] ShiftRowsInverse(byte[] state) //Inverse ShiftRows
        {
            byte[] shiftedRows = new byte[16];
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    //similiarly to normal ShiftRows, but the rows are shifted to the right
                    if (col - row < 0)
                    {
                        //if (row - col) < 0, then that byte is moved back to the start
                        //so we add 4 before multiplying (it would go out of bounds otherwise)
                        shiftedRows[col * 4 + row] = state[4 * (4 + (col - row)) + row];
                    }
                    else
                    {
                        //if (row - col) >= 0, then we can just use (col - row) to calculate where to take the byte from
                        shiftedRows[col * 4 + row] = state[4 * (col - row) + row];
                    }
                }
            }
            return shiftedRows;
        }

        private byte[] MixColumns(byte[] state) //MixColumns
        {
            byte[] MixedColumns = new byte[16];
            byte[] column = new byte[4]; //array with column that we are using to multiply
            for (int i = 0; i < 16; i++)
            {
                int k = 0;
                for (int j = i - (i % 4); j < i - (i % 4) + 4; j++)
                {
                    column[k++] = state[j]; //for each byte we get the column that it is in, so we can use it to multiply

                    byte result = 0;
                    byte[] tmp = new byte[4];

                    for (int l = 0; l < 4; l++)
                    {
                        tmp[l] = HexadecimalMultiplication(column[l], mixColumnsBox[4 * (i % 4) + l]);
                        //we multiply hexadecimaly each byte in column with corresponding value from fixed box
                        //(they are multiplied modulo x^4 + 1 with fixed polynomial a(x) = (03)x^3 + (01)x^2 + (01)x + (02)
                        result ^= tmp[l]; //we xor each multiplication result
                    }
                    MixedColumns[i] = result; //and finally we get the result for this byte
                }
            }

            return MixedColumns;
        }

        private byte[] MixColumnsInverse(byte[] state) //Inverse MixColumns
        {
            byte[] MixedColumns = new byte[16];
            byte[] column = new byte[4];
            for (int i = 0; i < 16; i++)
            {
                int k = 0;
                for (int j = i - (i % 4); j < i - (i % 4) + 4; j++)
                {
                    column[k++] = state[j];

                    byte result = 0;
                    byte[] tmp = new byte[4];

                    for (int l = 0; l < 4; l++)
                    {
                        tmp[l] = HexadecimalMultiplication(column[l], mixColumnsBoxInverse[4 * (i % 4) + l]);
                        //same as normal MixColumns but we use different fixed box
                        //because a^-1(x) = (0b)x^3 + (0d)x^2 + (09)x + (0e)
                        result ^= tmp[l];
                    }
                    MixedColumns[i] = result;
                }
            }

            return MixedColumns;
        }

        private byte HexadecimalMultiplication(byte a, byte b)
        {
            int result = 0;
            int aTmp;
            int bTmp;
            for (int i = 0; i < 8; i++)
            { //we go through each bit in byte a
                for (int j = 0; j < 8; j++)
                { //we go through each bit in byte b
                    aTmp = a & (1 << i); //we set the value of aTmp = 2^i if the corresponding bit in byte a is 1
                    bTmp = b & (1 << j); //we set the value of bTmp = 2^i if the corresponding bit in byte b is 1
                    if (aTmp != 0 && bTmp != 0)
                    { //we multiply only if both aTmp and bTmp are != 0
                      //then we set 1 at i+j index of result
                      //if 1 already exists we can make switch it to 0 (because coefficient has to be in GF(2))
                        result ^= (1 << (i + j));
                    }
                }
            }
            if (result > 0xff)  //we check for byte overflow, and use irreducible Polynomial Theorem GF(2^3):
                                //x^8 = x^4 + x^3 + x + 1 (0001 1011(2) = 1b) and so on
            {
                if ((1 & (result >> 11)) == 1)
                {
                    result ^= 0xd8;
                }
                if ((1 & (result >> 10)) == 1)
                {
                    result ^= 0x6c;
                }
                if ((1 & (result >> 9)) == 1)
                {
                    result ^= 0x36;
                }
                if ((1 & (result >> 8)) == 1)
                {
                    result ^= 0x1b;
                }
            }
            byte resultByte = (byte)result;
            return resultByte;
        }

        private byte[] EncryptBlock(byte[] block) //encryption for a single block
        {
            byte[] cipher = AddRoundKey(block, 0); //round 0 AddRoundKey

            for (int i = 0; i < rounds - 1; i++) //rounds from 1 to (number_of_rounds - 1)
            {
                cipher = SubBytes(cipher);
                cipher = ShiftRows(cipher);
                cipher = MixColumns(cipher);
                cipher = AddRoundKey(cipher, i + 1);
            }

            cipher = SubBytes(cipher);
            cipher = ShiftRows(cipher);
            cipher = AddRoundKey(cipher, rounds);
            return cipher;
        }

        private byte[] DecryptBlock(byte[] block) //decryption for a single block
        {
            byte[] cipher = AddRoundKey(block, rounds); //last round AddRoundKey (we are decrementing rounds)

            for (int i = rounds - 1; i > 0; i--) //rounds from (number_of_rounds) to 2 (the last AddRoundKey and MixColumns are from round 1)
            {
                cipher = ShiftRowsInverse(cipher);
                cipher = SubBytesInverse(cipher);
                cipher = AddRoundKey(cipher, i);
                cipher = MixColumnsInverse(cipher);
            }

            cipher = ShiftRowsInverse(cipher); //round 1 continued
            cipher = SubBytesInverse(cipher);
            cipher = AddRoundKey(cipher, 0); //round 0 AddRoundKey

            return cipher;
        }

        public byte[] Encrypt(byte[] plainText, byte[] key)
        {
            GenerateExpandedKey(key);
            int remainingBytes = plainText.Length % 16;
            int blocks = (plainText.Length / 16) + 1; //we check how many blocks we need to divide the text into
                                                      //if remainingBytes = 0, we have an additional block with zeros
            int numberOfAllBytes = blocks * 16;
            byte[] cipher = new byte[numberOfAllBytes];
            byte[] textToEncrypt = new byte[numberOfAllBytes];

            for (int i = 0; i < plainText.Length; i++)
            {
                textToEncrypt[i] = plainText[i];
            }

            
            for (int i = plainText.Length; i < numberOfAllBytes; i++)
            {
                //we set excess bytes to zeros
                textToEncrypt[i] = 0;
            }
            textToEncrypt[numberOfAllBytes - 1] = (byte)(16 - remainingBytes); //last byte is the number of zeros that were added

            byte[] tmpBlock = new byte[16];

            for (int i = 0; i < blocks; i++)
            {
                Array.Copy(textToEncrypt, i * 16, tmpBlock, 0, 16);
                tmpBlock = EncryptBlock(tmpBlock); //we encrypt a single block
                Array.Copy(tmpBlock, 0, cipher, i * 16, 16);
            }

            return cipher;
        }


        public byte[] Decrypt(byte[] cipher, byte[] key)
        {
            GenerateExpandedKey(key);
            if (cipher.Length % 16 != 0) throw new AESException("Wrong size of the cipher");

            int blocks = cipher.Length / 16; //we check how many block the cipher contains

            byte[] tmpBlock = new byte[16];
            byte[] decipheredText = new byte[cipher.Length];

            for (int i = 0; i < blocks; i++)
            {
                Array.Copy(cipher, i * 16, tmpBlock, 0, 16);
                tmpBlock = DecryptBlock(tmpBlock); //we decrypt a single block
                Array.Copy(tmpBlock, 0, decipheredText, i * 16, 16);
            }

            int numOfZeros = decipheredText[decipheredText.Length - 1];
            int sizeWithoutZeros = decipheredText.Length - numOfZeros; //we calculate the size without the excess zeros

            byte[] text = new byte[sizeWithoutZeros];

            Array.Copy(decipheredText, text, sizeWithoutZeros);
            return text;
        }

        public byte[] GenerateKey(int keyLength) //function for random key generation
        {
            byte[] generatedKey = new byte[keyLength / 8];
            Random rnd = new Random();
            rnd.NextBytes(generatedKey);
            return generatedKey;
        }

    }
}

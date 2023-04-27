using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;

namespace AES.Tests
{
    [TestClass()]
    public class AesTests
    {
        [TestMethod()]
        public void EncryptTest()
        {
            string keyS = "4D635166546A576E5A72347537782141";
            string plainTextS = "00000101030307070f0f1f1f3f3f";
            byte[] key = Convert.FromHexString(keyS);
            byte[] plainText = Convert.FromHexString(plainTextS);
            Aes aes = new Aes();
            byte[] result = aes.Encrypt(plainText, key);
            byte[] expected = Convert.FromHexString("95cf978a2c6ecd6aba289095a794f791");
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        [TestMethod()]
        public void DecryptTest()
        {
            string keyS = "4D635166546A576E5A72347537782141";
            string encryptedS = "95cf978a2c6ecd6aba289095a794f791";
            byte[] key = Convert.FromHexString(keyS);
            byte[] encrypted = Convert.FromHexString(encryptedS);
            Aes aes = new Aes();
            byte[] result = aes.Decrypt(encrypted, key);
            byte[] expected = Convert.FromHexString("00000101030307070f0f1f1f3f3f");
            Assert.IsTrue(result.SequenceEqual(expected));
        }


        [TestMethod()]
        public void EncryptTestSize128bit()
        {
            string keyS = "4D635166546A576E5A72347537782141";
            string plainTextS = "00000101030307070f0f1f1f3f3f7f7f";
            byte[] key = Convert.FromHexString(keyS);
            byte[] plainText = Convert.FromHexString(plainTextS);
            Aes aes = new Aes();
            byte[] result = aes.Encrypt(plainText, key);
            byte[] expected = Convert.FromHexString("5D857968A3A79E4379127280AF902852A4DD969BF08F1B991BD89CCBD21669F8");
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        [TestMethod()]
        public void DecryptTestSize128bit()
        {
            string keyS = "4D635166546A576E5A72347537782141";
            string encryptedS = "5D857968A3A79E4379127280AF902852A4DD969BF08F1B991BD89CCBD21669F8";
            byte[] key = Convert.FromHexString(keyS);
            byte[] encrypted = Convert.FromHexString(encryptedS);
            Aes aes = new Aes();
            byte[] result = aes.Decrypt(encrypted, key);
            byte[] expected = Convert.FromHexString("00000101030307070f0f1f1f3f3f7f7f");
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        [TestMethod()]
        public void EncryptTest192bitKey()
        {
            string keyS = "000102030405060708090a0b0c0d0e0f1011121314151617";
            string plainTextS = "00000101030307070f0f1f1f3f3f7f7f";
            byte[] key = Convert.FromHexString(keyS);
            byte[] plainText = Convert.FromHexString(plainTextS);
            Aes aes = new Aes();
            byte[] result = aes.Encrypt(plainText, key);
            byte[] expected = Convert.FromHexString("a061e0d8646d7412279593650bf37d7316271157db26b4c85f8574de3b3fe20d");
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        [TestMethod()]
        public void DecryptTestSize192bitKey()
        {
            string keyS = "000102030405060708090a0b0c0d0e0f1011121314151617";
            string encryptedS = "a061e0d8646d7412279593650bf37d7316271157db26b4c85f8574de3b3fe20d";
            byte[] key = Convert.FromHexString(keyS);
            byte[] encrypted = Convert.FromHexString(encryptedS);
            Aes aes = new Aes();
            byte[] result = aes.Decrypt(encrypted, key);
            byte[] expected = Convert.FromHexString("00000101030307070f0f1f1f3f3f7f7f");
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        [TestMethod()]
        public void EncryptTest256bitKey()
        {
            string keyS = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
            string plainTextS = "00000101030307070f0f1f1f3f3f7f7f";
            byte[] key = Convert.FromHexString(keyS);
            byte[] plainText = Convert.FromHexString(plainTextS);
            Aes aes = new Aes();
            byte[] result = aes.Encrypt(plainText, key);
            byte[] expected = Convert.FromHexString("75119223894595f9bd8db46a43558f042b347c88e5c9c8ff0b7a121b687bd06d");
            Assert.IsTrue(result.SequenceEqual(expected));
        }

        [TestMethod()]
        public void DecryptTestSize256bitKey()
        {
            string keyS = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
            string encryptedS = "75119223894595f9bd8db46a43558f042b347c88e5c9c8ff0b7a121b687bd06d";
            byte[] key = Convert.FromHexString(keyS);
            byte[] encrypted = Convert.FromHexString(encryptedS);
            Aes aes = new Aes();
            byte[] result = aes.Decrypt(encrypted, key);
            byte[] expected = Convert.FromHexString("00000101030307070f0f1f1f3f3f7f7f");
            Assert.IsTrue(result.SequenceEqual(expected));
        }
    }
}
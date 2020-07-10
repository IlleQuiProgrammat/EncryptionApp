using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace UnitTests.CryptoTests
{
    using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
    using System;
    using System.Linq;
    using Xunit;

    public class SymmetricEncryptionUnitTest
    {
        [Theory]
        [ClassData(typeof(SymmetricEncryptionData))]
        public void CleanRoundtripBytes(SymmetricCryptoManager testCryptoManager)
        {
            var rng = new Random();
            var data = new byte[1064 * 1064];
            var iv = new byte[64];
            var key = new byte[64];

            rng.NextBytes(data);
            rng.NextBytes(iv);
            rng.NextBytes(key);

            byte[] encryptedBytes = testCryptoManager.EncryptBytes(data, key.Take(testCryptoManager.KeySize / 8).ToArray(), iv);
            byte[] decryptedBytes = testCryptoManager.DecryptBytes(encryptedBytes, key.Take(testCryptoManager.KeySize / 8).ToArray(), iv);

            Assert.True(data.SequenceEqual(decryptedBytes));
        }

        [Theory]
        [ClassData(typeof(SymmetricEncryptionData))]
        public void TestBytesEarlyIv(SymmetricCryptoManager testCryptoManager)
        {
            var rng = new Random();
            var data = new byte[1064 * 1064];
            var iv = new byte[64];
            var key = new byte[64];

            rng.NextBytes(data);
            rng.NextBytes(iv);
            rng.NextBytes(key);

            testCryptoManager.InitializationVector = iv;

            byte[] encryptedData = testCryptoManager.EncryptBytes(data, key.Take(testCryptoManager.KeySize / 8).ToArray());
            byte[] decryptedBytes = testCryptoManager.DecryptBytes(encryptedData, key.Take(testCryptoManager.KeySize / 8).ToArray());

            Assert.True(data.SequenceEqual(decryptedBytes));
        }

        [Theory]
        [ClassData(typeof(SymmetricEncryptionData))]
        public void TestBadKey(SymmetricCryptoManager testCryptoManager)
        {
            var rng = new Random();
            var data = new byte[1064 * 1064];
            var iv = new byte[64];
            var key = new byte[64];
            var badKey = new byte[64];

            rng.NextBytes(data);
            rng.NextBytes(iv);
            rng.NextBytes(key);
            rng.NextBytes(badKey);

            byte[] encryptedData = testCryptoManager.EncryptBytes(data, key.Take(testCryptoManager.KeySize / 8).ToArray(), iv);

            var shouldFail = new Action(() =>
            {
                _ = testCryptoManager.DecryptBytes(encryptedData, badKey.Take(testCryptoManager.KeySize / 8).ToArray(), iv);
            });

            Assert.Throws<CryptographicException>(shouldFail);
        }

        [Theory]
        [ClassData(typeof(SymmetricEncryptionData))]
        public void TestBadData(SymmetricCryptoManager testCryptoManager)
        {
            var rng = new Random();
            var iv = new byte[64];
            var key = new byte[64];
            var badData = new byte[1064 * 1064];

            rng.NextBytes(iv);
            rng.NextBytes(key);
            rng.NextBytes(badData);

            var shouldFail = new Action(() =>
            {
                _ = testCryptoManager.DecryptBytes(badData, key.Take(testCryptoManager.KeySize / 8).ToArray(), iv);
            });

            Assert.Throws<CryptographicException>(shouldFail);
        }
    }

    public class SymmetricEncryptionData : IEnumerable<object[]>
    {
        public IEnumerator<object[]> GetEnumerator()
        {
            yield return new object[] { new AesCryptoManager(new AesCng { KeySize = 192 }) };
            yield return new object[] { new TripleDesCryptoManager(new TripleDESCng { KeySize = 192 }) };
            yield return new object[] { new Rc2CryptoManager(new RC2CryptoServiceProvider { KeySize = 128 }) };
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
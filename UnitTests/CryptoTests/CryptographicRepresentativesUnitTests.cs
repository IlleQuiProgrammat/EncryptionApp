using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.Information.Representatives;
using Xunit;

namespace UnitTests.CryptoTests
{
    public class CryptographicRepresentativesUnitTests
    {
        [Fact]
        public void TestHeader()
        {
            var transform = new TransformationRepresentative(typeof(AesCryptoManager), new byte[] { 1, 2, 3 }, CipherMode.CTS, PaddingMode.PKCS7, 128, 128);
            var key = new KeyRepresentative(typeof(Pbkdf2KeyDerive), 128UL, new byte[] { 1, 2, 3 });
            var hmac = new HmacRepresentative(typeof(HMACMD5), new byte[] { 1, 2, 3 });
            var data = new SymmetricCryptographicRepresentative(transform, key, hmac);
            var dataTwo = new SymmetricCryptographicRepresentative();
            const string path = @"C:\Users\johnk\source\repos\EncryptionApp\localpath.txt";

            data.WriteHeaderToFile(path);

            dataTwo.ReadHeaderFromFile(path);

            File.Delete(path);

            Assert.True(data.Equals(dataTwo));
        }
    }
}

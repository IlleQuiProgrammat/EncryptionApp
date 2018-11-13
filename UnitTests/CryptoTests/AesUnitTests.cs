using System.Collections.Generic;
using System.Reflection;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.Information.Representatives;

namespace UnitTests.CryptoTests
{
    using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;
    using Xunit;

    public class AesUnitTests
    {

        [Fact]
        public void TestHeader()
        {
            var transform = new TransformationRepresentative(typeof(AesCryptoManager), new byte[] { 1, 2, 3 }, CipherMode.CTS, PaddingMode.PKCS7, 128, 128);
            var key = new KeyRepresentative(typeof(Pbkdf2KeyDerive), 128UL, new byte[] { 1, 2, 3 });
            var hmac = new HmacRepresentative(typeof(HMACMD5), new byte[] { 1, 2, 3 });
            var data = new SymmetricCryptographicRepresentative(transform, key, hmac);
            data.WriteHeaderToFile(@"C:\Users\johnk\source\repos\EncryptionApp\localpath.txt");
            var dataTwo = new SymmetricCryptographicRepresentative();
            dataTwo.ReadHeaderFromFile(@"C:\Users\johnk\source\repos\EncryptionApp\localpath.txt");

            FieldInfo[] fields = typeof(SymmetricCryptographicRepresentative).GetFields(BindingFlags.Public |
                                                                                        BindingFlags.NonPublic |
                                                                                        BindingFlags.Instance);

            PropertyInfo[] properties = typeof(SymmetricCryptographicRepresentative).GetProperties(BindingFlags.Public |
                                                                                                   BindingFlags.NonPublic |
                                                                                                   BindingFlags.Instance);

            var writeStrings = new List<string>();

            foreach (FieldInfo field in fields)
            {
                writeStrings.Add("Data value:" + field.Name + field.GetValue(data));
                writeStrings.Add("DataTwo value:" + field.Name + field.GetValue(dataTwo));
            }

            foreach (PropertyInfo property in properties)
            {
                if (property.Name == "HeaderLength") continue;
                writeStrings.Add("Data value:" + property.Name + property.GetValue(data));
                writeStrings.Add("DataTwo value:" + property.Name + property.GetValue(dataTwo));
            }

            writeStrings.Add("Data: " + string.Join(" ", data.HmacRepresentative.Value.HashBytes.Select(valueHashByte => valueHashByte.ToString())));
            writeStrings.Add("Data two: " + string.Join(" ", data.HmacRepresentative.Value.HashBytes.Select(valueHashByte => valueHashByte.ToString())));

            File.WriteAllLines(@"C:\Users\johnk\source\repos\EncryptionApp\local.txt", writeStrings);

            Debug.Assert(data.Equals(dataTwo));
        }
    }
}
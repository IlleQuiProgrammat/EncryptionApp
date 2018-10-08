﻿using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTests
{
    [TestClass]
    public class AesUnitTests
    {
        private readonly string _assetsFolder = Path.GetTempPath() + @"\EncryptionApp\assets\";

        [TestInitialize]
        public void Initializer()
        {
            Directory.CreateDirectory(_assetsFolder);

            var data = new byte[1024 * 1024];
            var rng = new Random();
            rng.NextBytes(data);
            File.WriteAllBytes(_assetsFolder + "testFile.txt", data);
        }

        [TestCleanup]
        public void Cleanup()
        {
            Directory.Delete(_assetsFolder, true);
        }

        [TestMethod]
        public void TestMegabyte()
        {
            var testEncryptionHandler = new CryptoTools.AesCryptoManager();
            var key = testEncryptionHandler.GenerateKey(256);
            testEncryptionHandler.EncryptFileBytes(_assetsFolder + "testFile.txt", _assetsFolder + "EncryptedTestFile.txt",
                key);

            testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt",
                key);
            
            using (var unencryptedFileReader = new BinaryReader(File.OpenRead(_assetsFolder + "TestFile.txt")))
            using (var decryptedFileReader = new BinaryReader(File.OpenRead(_assetsFolder + "DecryptedTestFile.txt")))
            {
                while (true)
                {
                    try
                    {
                        Debug.Assert(unencryptedFileReader.ReadByte() == decryptedFileReader.ReadByte(), "Failed decrypting - file corrupted");
                    }
                    catch (EndOfStreamException)
                    {
                        break;
                    }
                }
            }
        }

        [TestMethod]
        public void TestBadKey()
        {
            var testEncryptionHandler = new CryptoTools.AesCryptoManager();
            var key = testEncryptionHandler.GenerateKey(256);
            var badKey = testEncryptionHandler.GenerateKey(256);
            if (key.SequenceEqual(badKey)) { throw new ExternalException("What the $@#%"); }

            testEncryptionHandler.EncryptFileBytes(_assetsFolder + "TestFile.txt", _assetsFolder + "EncryptedTestFile.txt",
                badKey);

            testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt",
                badKey);

            Debug.Assert(testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt",
                key) == false, "Used fake key, didn't register it as so");
        }

        [TestMethod]
        public void TestBadFile()
        {
            var testEncryptionHandler = new CryptoTools.AesCryptoManager();
            var key = testEncryptionHandler.GenerateKey(256);

            var data = new byte[1024 * 1024];
            var rng = new Random();
            rng.NextBytes(data);
            File.WriteAllBytes(_assetsFolder + "EncryptedtestFile.txt", data);

            Debug.Assert(testEncryptionHandler.DecryptFileBytes(_assetsFolder + "EncryptedTestFile.txt", _assetsFolder + "DecryptedTestFile.txt",
                             key) == false, "Used corrupt file, didn't register it as so");
        }
    }
}

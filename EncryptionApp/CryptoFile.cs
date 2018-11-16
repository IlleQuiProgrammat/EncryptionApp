using Encryption_App.UI;
using FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using FactaLogicaSoftware.CryptoTools.Exceptions;
using FactaLogicaSoftware.CryptoTools.HMAC;
using FactaLogicaSoftware.CryptoTools.Information.Representatives;
using FactaLogicaSoftware.CryptoTools.PerformanceInterop;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Windows;
using JetBrains.Annotations;

namespace Encryption_App
{
    internal class CryptoFile
    {
        private readonly string _filePath;
        private readonly Progress<int> _progress;

        public CryptoFile(string filePath)
        {
            this._filePath = filePath;
            this._progress = null;
        }

        public CryptoFile(string filePath, Progress<int> progress)
        {
            this._filePath = filePath;
            this._progress = progress;
        }

        public bool FileContainsHeader()
        {
            var buff = new char[1024];
            string checkString;

            try
            {
                using (var reader = new StreamReader(this._filePath))
                {
                    try
                    {
                        reader.ReadBlock(buff, 0, buff.Length);
                    }
                    catch (IOException e)
                    {
                        FileStatics.WriteToLogFile(e);
                        MessageBox.Show("Unknown fatal IO exception occured - check log file for details");
                        throw;
                    }

                    checkString = new string(buff);
                }
            }
            catch (IOException e)
            {
                FileStatics.WriteToLogFile(e);
                MessageBox.Show("Unknown fatal IO exception occured - check log file for details");
                throw;
            }

            return checkString.IndexOf(CryptographicRepresentative.StartChars, StringComparison.Ordinal) != -1 &&
                   checkString.IndexOf(CryptographicRepresentative.EndChars, StringComparison.Ordinal) != -1;
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="request"></param>
        /// <param name="password"></param>
        /// <param name="desiredKeyDerivationMilliseconds"></param>
        public void EncryptDataWithHeader(RequestStateRecord request, SecureString password,
            int desiredKeyDerivationMilliseconds)
        {
            if (request.Contract.InstanceKeyContract == null) throw new ArgumentNullException(nameof(request));

            ((IProgress<int>)this._progress)?.Report(0);
            password.MakeReadOnly();


            var salt = new byte[request.Contract.InstanceKeyContract.Value.SaltLengthBytes];

            var iv = new byte[request.Contract.TransformationContract.InitializationVectorSizeBytes];
            var rng = new RNGCryptoServiceProvider();
            try
            {
                rng.GetBytes(salt);
                rng.GetBytes(iv);
            }
            catch (CryptographicException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show(
                    "There was an error generating secure random numbers. Please try again - check log file for more details");
            }

            var performanceDerivative =
                    new PerformanceDerivative(request.Contract.InstanceKeyContract.Value.PerformanceDerivative);
            

            ((IProgress<int>)this._progress)?.Report(25);

            // Get the password

            if (password.Length == 0)
            {
                MessageBox.Show("You must enter a password");

                ((IProgress<int>)this._progress)?.Report(0);
                return;
            }
#if TRACE
            if (password.Length < App.This.CurrentSettings.MinPasswordLength)
            {
                MessageBox.Show("Password too short");
                ((IProgress<int>)_progress)?.Report(0);
                return;
            }
#endif
            GCHandle byteHandle = SecureStringConverter.SecureStringToKeyDerive(password, salt,
                performanceDerivative, request.Contract.InstanceKeyContract.Value.KeyAlgorithm, out KeyDerive keyDevice);

            ((IProgress<int>)this._progress)?.Report(35);

            HMAC hmacAlg = null;

            if (request.Contract.HmacContract != null)
            {
                // Create the algorithm using reflection
                hmacAlg = (HMAC) Activator.CreateInstance(request.Contract.HmacContract.Value.HashAlgorithm);
            }

            Aes aesAlgorithm = new AesCng
            {
                BlockSize = (int)request.Contract.TransformationContract.BlockSize,
                KeySize = (int)request.Contract.TransformationContract.KeySize,
                Mode = request.Contract.TransformationContract.CipherMode,
                Padding = request.Contract.TransformationContract.PaddingMode
            };

            var @params = new object[] { 1024 * 1024 * 1024, aesAlgorithm };

            var encryptor =
                (SymmetricCryptoManager)Activator.CreateInstance(request.Contract.TransformationContract.CryptoManager,
                    @params);


            byte[] key = keyDevice.GetBytes((int)request.Contract.TransformationContract.KeySize / 8);

            Externals.ZeroMemory(byteHandle.AddrOfPinnedObject(), ((byte[])byteHandle.Target).Length);

            byteHandle.Free();

            // Create a handle to the key to allow control of it
            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

            // Encrypt the data to a temporary file
            encryptor.EncryptFileBytes(this._filePath, App.This.DataTempFile, key, iv);

            ((IProgress<int>)this._progress)?.Report(90);


            byte[] hash = null;

            if (request.Contract.HmacContract != null)
            {
                // Create the signature derived from the encrypted data and key
                byte[] signature = MessageAuthenticator.CreateHmac(App.This.DataTempFile, key, hmacAlg);

                // Set the signature correctly in the CryptographicRepresentative object
                hash = signature;
            }

            HmacRepresentative? hmac = request.Contract.HmacContract.HasValue
                                        ? new HmacRepresentative(request.Contract.HmacContract.Value.HashAlgorithm, hash)
                                        : (HmacRepresentative?)null;

            KeyRepresentative? keyRepresentative = new KeyRepresentative
            (
                request.Contract.InstanceKeyContract.Value.KeyAlgorithm,
                request.Contract.InstanceKeyContract.Value.PerformanceDerivative,
                salt
            );

            // Delete the key from memory for security
            Externals.ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
            keyHandle.Free();

            var cryptographicInfo = new SymmetricCryptographicRepresentative
            (
                new TransformationRepresentative
                (
                    request.Contract.TransformationContract.CryptoManager,
                    iv,
                    request.Contract.TransformationContract.CipherMode,
                    request.Contract.TransformationContract.PaddingMode,
                    request.Contract.TransformationContract.KeySize,
                    request.Contract.TransformationContract.BlockSize
                ),
                keyRepresentative,
                hmac
            );

            // Write the CryptographicRepresentative object to a file
            cryptographicInfo.WriteHeaderToFile(this._filePath);

            ((IProgress<int>)this._progress)?.Report(98);
            FileStatics.AppendToFile(this._filePath, App.This.DataTempFile);

            ((IProgress<int>)this._progress)?.Report(100);
        }

        ///  <summary>
        /// 
        ///  </summary>
        ///  <param name="request"></param>
        /// <param name="key"></param>
        /// <param name="desiredKeyDerivationMilliseconds"></param>
        public void EncryptDataWithHeader(RequestStateRecord request, byte[] key,
            int desiredKeyDerivationMilliseconds)
        {
            ((IProgress<int>)this._progress)?.Report(0);

            var iv = new byte[request.Contract.TransformationContract.InitializationVectorSizeBytes];
            var rng = new RNGCryptoServiceProvider();
            try
            {
                rng.GetBytes(iv);
            }
            catch (CryptographicException exception)
            {
                FileStatics.WriteToLogFile(exception);
                MessageBox.Show(
                    "There was an error generating secure random numbers. Please try again - check log file for more details");
            }

            ((IProgress<int>)this._progress)?.Report(25);

            HMAC hmacAlg = null;

            if (request.Contract.HmacContract != null)
            {
                // Create the algorithm using reflection
                hmacAlg = (HMAC)Activator.CreateInstance(request.Contract.HmacContract.Value.HashAlgorithm);
            }

            var @params = new object[] { 1024 * 1024 * 1024, new AesCryptoServiceProvider() };

            var encryptor =
                (SymmetricCryptoManager)Activator.CreateInstance(request.Contract.TransformationContract.CryptoManager,
                    @params);
            
            // Create a handle to the key to allow control of it
            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

            // Encrypt the data to a temporary file
            encryptor.EncryptFileBytes(this._filePath, App.This.DataTempFile, key, iv);

            ((IProgress<int>)this._progress)?.Report(90);


            byte[] hash = null;

            if (request.Contract.HmacContract != null)
            {
                // Create the signature derived from the encrypted data and key
                byte[] signature = MessageAuthenticator.CreateHmac(App.This.DataTempFile, key, hmacAlg);

                // Set the signature correctly in the CryptographicRepresentative object
                hash = signature;
            }

            HmacRepresentative? hmac = request.Contract.HmacContract != null && hash != null
                                        ? new HmacRepresentative(request.Contract.HmacContract.Value.HashAlgorithm, hash)
                                        : (HmacRepresentative?)null;

            // Delete the key from memory for security
            Externals.ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
            keyHandle.Free();

            var cryptographicInfo = new SymmetricCryptographicRepresentative
            (
                new TransformationRepresentative
                (
                    request.Contract.TransformationContract.CryptoManager,
                    iv,
                    request.Contract.TransformationContract.CipherMode,
                    request.Contract.TransformationContract.PaddingMode,
                    request.Contract.TransformationContract.KeySize,
                    request.Contract.TransformationContract.BlockSize
                ),
                null,
                hmac
            );

            // Write the CryptographicRepresentative object to a file
            cryptographicInfo.WriteHeaderToFile(this._filePath);

            ((IProgress<int>)this._progress)?.Report(98);

            FileStatics.AppendToFile(this._filePath, App.This.DataTempFile);

            ((IProgress<int>)this._progress)?.Report(100);

        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="cryptographicRepresentative"></param>
        /// <param name="password"></param>
        /// TODO decompose
        public void DecryptDataWithHeader(SymmetricCryptographicRepresentative cryptographicRepresentative, SecureString password)
        {
            if (cryptographicRepresentative == null)
                throw new ArgumentNullException(nameof(cryptographicRepresentative));

            if (cryptographicRepresentative.InstanceKeyCreator == null)
                throw new ArgumentNullException(nameof(cryptographicRepresentative.InstanceKeyCreator));

            ((IProgress<int>)this._progress)?.Report(0);
            password.MakeReadOnly();

            var performanceDerivative = new PerformanceDerivative(cryptographicRepresentative.InstanceKeyCreator.Value.PerformanceDerivative);

            GCHandle byteHandle = SecureStringConverter.SecureStringToKeyDerive(password, cryptographicRepresentative.InstanceKeyCreator.Value.Salt,
                performanceDerivative, cryptographicRepresentative.InstanceKeyCreator.Value.KeyAlgorithm, out KeyDerive keyDevice);

            ((IProgress<int>)this._progress)?.Report(10);


            HMAC hmacAlg = null;

            if (cryptographicRepresentative.HmacRepresentative != null)
            {
                hmacAlg = (HMAC)Activator.CreateInstance(cryptographicRepresentative.HmacRepresentative.Value.HashAlgorithm);
            }

            var @params = new object[]
            {
                1024 * 1024 * 8, new AesCng
                {
                    BlockSize = (int)cryptographicRepresentative.TransformationModeInfo.BlockSize,
                    KeySize = (int)cryptographicRepresentative.TransformationModeInfo.KeySize,
                    Mode = cryptographicRepresentative.TransformationModeInfo.CipherMode,
                    Padding = cryptographicRepresentative.TransformationModeInfo.PaddingMode
                }
            };


            var decryptor = (SymmetricCryptoManager)Activator.CreateInstance(cryptographicRepresentative.TransformationModeInfo.CryptoManager, @params);

            FileStatics.RemovePrependData(this._filePath, App.This.HeaderLessTempFile, cryptographicRepresentative.HeaderLength);

            ((IProgress<int>)this._progress)?.Report(20);


            byte[] key = keyDevice.GetBytes((int)cryptographicRepresentative.TransformationModeInfo.KeySize / 8);

            Externals.ZeroMemory(byteHandle.AddrOfPinnedObject(), ((byte[])byteHandle.Target).Length);

            byteHandle.Free();

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

            var isVerified = false;

            if (cryptographicRepresentative.HmacRepresentative != null)
            {
                // Check if the file and key make the same HMAC
                isVerified = MessageAuthenticator.VerifyHmac(App.This.HeaderLessTempFile, key,
                    cryptographicRepresentative.HmacRepresentative.Value.HashBytes, hmacAlg);
            }

            ((IProgress<int>)this._progress)?.Report(35);

            // If that didn't succeed, the file has been tampered with
            if (cryptographicRepresentative.HmacRepresentative != null && !isVerified)
            {
                throw new UnverifiableDataException("File could not be verified - may have been tampered, or the password is incorrect");
            }

            // Try decrypting the remaining data
            try
            {

                decryptor.DecryptFileBytes(App.This.HeaderLessTempFile, App.This.DataTempFile, key, cryptographicRepresentative.TransformationModeInfo.InitializationVector);

                // Move the file to the original file location
                File.Copy(App.This.DataTempFile, this._filePath, true);
                ((IProgress<int>)this._progress)?.Report(100);

            }
            finally
            {
                // Delete the key from memory for security
                Externals.ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
                keyHandle.Free();
            }
        }

        ///  <summary>
        /// 
        ///  </summary>
        ///  <param name="cryptographicRepresentative"></param>
        /// <param name="key"></param>
        /// TODO decompose
        public void DecryptDataWithHeader([NotNull] SymmetricCryptographicRepresentative cryptographicRepresentative, byte[] key)
        {
            ((IProgress<int>)this._progress)?.Report(0);

            ((IProgress<int>)this._progress)?.Report(10);
            
            HMAC hmacAlg = null;

            if (cryptographicRepresentative.HmacRepresentative != null)
            {
                hmacAlg = (HMAC)Activator.CreateInstance(cryptographicRepresentative.HmacRepresentative.Value.HashAlgorithm);
            }

            var @params = new object[]
            {
                1024 * 1024 * 8, new AesCng
                {
                    BlockSize = (int)cryptographicRepresentative.TransformationModeInfo.BlockSize,
                    KeySize = (int)cryptographicRepresentative.TransformationModeInfo.KeySize,
                    Mode = cryptographicRepresentative.TransformationModeInfo.CipherMode,
                    Padding = cryptographicRepresentative.TransformationModeInfo.PaddingMode
                }
            };


            var decryptor = (SymmetricCryptoManager)Activator.CreateInstance(cryptographicRepresentative.TransformationModeInfo.CryptoManager, @params);

            FileStatics.RemovePrependData(this._filePath, App.This.HeaderLessTempFile, cryptographicRepresentative.HeaderLength);

            ((IProgress<int>)this._progress)?.Report(20);

            GCHandle keyHandle = GCHandle.Alloc(key, GCHandleType.Pinned);

            var isVerified = false;

            if (cryptographicRepresentative.HmacRepresentative != null)
            {
                // Check if the file and key make the same HMAC
                isVerified = MessageAuthenticator.VerifyHmac(App.This.HeaderLessTempFile, key,
                    cryptographicRepresentative.HmacRepresentative.Value.HashBytes, hmacAlg);
            }

            ((IProgress<int>)this._progress)?.Report(35);

            // If that didn't succeed, the file has been tampered with
            if (cryptographicRepresentative.HmacRepresentative != null && !isVerified)
            {
                throw new UnverifiableDataException("File could not be verified - may have been tampered, or the password is incorrect");
            }

            // Try decrypting the remaining data
            try
            {
                decryptor.DecryptFileBytes(App.This.HeaderLessTempFile, App.This.DataTempFile, key, cryptographicRepresentative.TransformationModeInfo.InitializationVector);

                ((IProgress<int>)this._progress)?.Report(75);

                // Move the file to the original file location
                File.Copy(App.This.DataTempFile, this._filePath, true);

                ((IProgress<int>)this._progress)?.Report(100);
            }
            finally
            {
                // Delete the key from memory for security
                Externals.ZeroMemory(keyHandle.AddrOfPinnedObject(), key.Length);
                keyHandle.Free();
            }
        }
    }
}
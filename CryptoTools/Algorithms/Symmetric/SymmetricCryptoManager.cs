using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using FactaLogicaSoftware.CryptoTools.Events;
using JetBrains.Annotations;

#if DEBUG

using FactaLogicaSoftware.CryptoTools.DebugTools;

#endif

namespace FactaLogicaSoftware.CryptoTools.Algorithms.Symmetric
{
    /// <inheritdoc />
    /// <summary>
    /// An interface that defines the contract of any encryption algorithm
    /// </summary>
    public abstract class SymmetricCryptoManager : IDisposable
    {
        private protected readonly SymmetricAlgorithm SymmetricAlgorithm;

        /// <summary>
        /// The event raised if the memory chunk size is changed
        /// due to memory limitations
        /// </summary>
        public event EventHandler<BufferSizeChangedEventArgs> MemoryChunkValueChanged;

        /// <summary>
        /// The number of bytes read into memory at one time
        /// </summary>
        protected int BufferSize;

        /// <summary>
        /// The key size, in bits, to use
        /// </summary>
        public abstract int KeySize { get; set; }

        /// <summary>
        /// The initialization vector used for transformation
        /// </summary>
        public abstract byte[] InitializationVector { get; set; }

        /// <summary>
        /// Whether the current SymmetricAlgorithm is FIPS 140-2 compliant
        /// </summary>
        public bool IsFipsCompliant { get; private protected set; }

        /// <summary>
        /// Uses custom read/write values and an AES algorithm of your choice
        /// </summary>
        /// <param name="bufferSize">The number of bytes to read and write</param>
        /// <param name="algorithm">The algorithm to use</param>
        protected SymmetricCryptoManager(int bufferSize, [NotNull] SymmetricAlgorithm algorithm)
        {
            // Assign to class field
            this.BufferSize = bufferSize;
            
            this.SymmetricAlgorithm = algorithm;
        }

        /// <summary>
        /// The default finalizer
        /// </summary>
        ~SymmetricCryptoManager()
        {
            Dispose(false);
        }

        /// <summary>
        /// The event handler for any change in the
        /// memory chunking size
        /// </summary>
        /// <param name="e">The new value wrapped in a BufferSizeChangedEventArgs object</param>
        /// <see cref="BufferSizeChangedEventArgs"/>
        protected void OnMemoryChunkValueChanged([NotNull] BufferSizeChangedEventArgs e)
        {
            EventHandler<BufferSizeChangedEventArgs> handler = this.MemoryChunkValueChanged;
            handler?.Invoke(this, e);
        }

        /// <summary>
        /// Generates a secure sequence of random numbers
        /// </summary>
        /// <param name="arrayToFill">The array to fill</param>
        /// <returns>A byte array that is the key</returns>
        public static void FillWithSecureValues(byte[] arrayToFill)
        {
            if (arrayToFill == null)
            {
                throw new ArgumentNullException(nameof(arrayToFill));
            }
            // Generates a random value
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(arrayToFill);
        }

        /// <summary>
        /// The transformation function used by all derived classes
        /// </summary>
        /// <param name="inputFile"></param>
        /// <param name="outputFile"></param>
        /// <param name="transformer"></param>
        protected void InternalTransformFile([NotNull] string inputFile, [NotNull] string outputFile, [NotNull] ICryptoTransform transformer)
        {
            FileStream outFileStream = File.Create(outputFile);
            using (var cs = new CryptoStream(outFileStream, transformer, CryptoStreamMode.Write))
            using (var inFile = new BinaryReader(File.OpenRead(inputFile)))
            {
                try
                {
                    inFile.BaseStream.CopyTo(cs, this.BufferSize);
                }
                catch (ArgumentException e)
                {
                    InternalDebug.WriteToDiagnosticsFile(e.Message);
                    throw;
                }
            }
        }

        /// <summary>
        /// If overriden in a derived class, encrypts bytes of a given file into another one
        /// </summary>
        /// <param name="inputFile">A string showing the full path of the path to encrypt</param>
        /// <param name="outputFile">The full path of the file to put the encrypted data</param>
        /// <param name="key">The bytes of the key</param>
        /// <param name="iv">The bytes of the initialization vector</param>
        public abstract void EncryptFileBytes([NotNull] string inputFile, [NotNull] string outputFile, [NotNull] byte[] key, [CanBeNull] byte[] iv = null);

        /// <summary>
        /// If overriden in a derived class, decrypts bytes of a given file into another one
        /// </summary>
        /// <param name="inputFile">A string showing the full path of the path to encrypt</param>
        /// <param name="outputFile">The full path of the file to put the encrypted data</param>
        /// <param name="key">The bytes of the key</param>
        /// <param name="iv">The bytes of the initialization vector</param>
        public abstract void DecryptFileBytes([NotNull] string inputFile, [NotNull] string outputFile, [NotNull] byte[] key, [CanBeNull] byte[] iv = null);

        /// <summary>
        /// If overriden in a derived class, encrypts an array of bytes
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="key">The key to encrypt with</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>The encrypted byte array</returns>
        public abstract byte[] EncryptBytes([NotNull] byte[] data, [NotNull] byte[] key, [CanBeNull] byte[] iv = null);

        /// <summary>
        /// If overriden in a derived class, decrypts an array of bytes
        /// </summary>
        /// <param name="data">The data to decrypt</param>
        /// <param name="key">The key to decrypt with</param>
        /// <param name="iv">The initialization vector</param>
        /// <returns>The decrypted byte array</returns>
        public abstract byte[] DecryptBytes([NotNull] byte[] data, [NotNull] byte[] key, [CanBeNull] byte[] iv = null);

        private void ReleaseUnmanagedResources()
        {
            // TODO release unmanaged resources here
        }

        private void Dispose(bool disposing)
        {
            ReleaseUnmanagedResources();
            if (disposing)
            {
                this.SymmetricAlgorithm?.Dispose();
            }
        }

        /// <inheritdoc />
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
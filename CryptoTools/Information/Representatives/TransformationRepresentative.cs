using System;
using System.Linq;
using System.Security.Cryptography;
using JetBrains.Annotations;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <inheritdoc cref="ValueType" />
    /// <summary>
    /// The information representing a piece
    /// of encrypted data
    /// </summary>
    public readonly struct TransformationRepresentative : IEquatable<TransformationRepresentative>
    {
        /// <summary>
        /// The CryptoManager used for transformation
        /// </summary>
        [NotNull]
        public readonly Type CryptoManager;

        /// <summary>
        /// The initialization vector
        /// </summary>
        [NotNull]
        public readonly byte[] InitializationVector;

        /// <summary>
        /// The CipherMode used
        /// </summary>
        public readonly CipherMode CipherMode;

        /// <summary>
        /// The key size, in bits, used
        /// </summary>
        public readonly uint KeySize;

        /// <summary>
        /// The block size, in bits, used
        /// </summary>
        public readonly uint BlockSize;

        /// <summary>
        /// The padding mode used
        /// </summary>
        public readonly PaddingMode PaddingMode;

        /// <summary>
        /// The constructor for this
        /// immutable class
        /// </summary>
        /// <param name="cryptoManager">The CryptoManager used for transformation</param>
        /// <param name="initializationVector">The initialization vector</param>
        /// <param name="cipherMode">The CipherMode used</param>
        /// <param name="keySize">The key size, in bits, used</param>
        /// <param name="blockSize">The block size, in bits, used</param>
        /// <param name="paddingMode"></param>
        /// <exception cref="ArgumentNullException"></exception>
        public TransformationRepresentative([NotNull] Type cryptoManager, [CanBeNull] byte[] initializationVector, CipherMode cipherMode, PaddingMode paddingMode, uint keySize, uint blockSize)
        {
            this.CryptoManager = cryptoManager ?? throw new ArgumentNullException(nameof(cryptoManager));
            this.InitializationVector = initializationVector ?? new byte[blockSize / 8];
            this.CipherMode = cipherMode;
            this.KeySize = keySize;
            this.BlockSize = blockSize;
            this.PaddingMode = paddingMode;
        }

        /// <inheritdoc />
        /// <summary>
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(TransformationRepresentative other)
        {
            return this.CryptoManager == other.CryptoManager &&
                   this.InitializationVector.SequenceEqual(other.InitializationVector) &&
                   this.CipherMode == other.CipherMode &&
                   this.KeySize == other.KeySize &&
                   this.BlockSize == other.BlockSize &&
                   this.PaddingMode == other.PaddingMode;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (obj == null) return false;
            return obj.GetType() == this.GetType() && Equals((TransformationRepresentative)obj);
        }

        /// <inheritdoc cref="ValueType" />
        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = this.CryptoManager.GetHashCode();
                hashCode = (hashCode * 397) ^ this.InitializationVector.GetHashCode();
                hashCode = (hashCode * 397) ^ (int)this.CipherMode;
                hashCode = (hashCode * 397) ^ (int)this.KeySize;
                hashCode = (hashCode * 397) ^ (int)this.BlockSize;
                hashCode = (hashCode * 397) ^ (int)this.PaddingMode;
                return hashCode;
            }
        }

        /// <inheritdoc cref="ValueType"/>
        public static bool operator ==(TransformationRepresentative left, TransformationRepresentative right)
        {
            return left.Equals(right);
        }

        /// <inheritdoc cref="ValueType"/>
        public static bool operator !=(TransformationRepresentative left, TransformationRepresentative right)
        {
            return !(left == right);
        }
    }
}
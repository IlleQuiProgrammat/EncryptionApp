using System;
using System.Linq;
using JetBrains.Annotations;
using Newtonsoft.Json;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <inheritdoc cref="ValueType" />
    /// <summary>
    /// The representation of a specific HMAC
    /// verification
    /// </summary>
    public readonly struct HmacRepresentative : IEquatable<HmacRepresentative>
    {
        /// <summary>
        /// The default constructor for this immutable object
        /// </summary>
        /// <param name="hashBytes"></param>
        /// <param name="hashAlgorithm"></param>
        [JsonConstructor]
        public HmacRepresentative([NotNull] Type hashAlgorithm, [NotNull] byte[] hashBytes)
        {
            if (!hashAlgorithm.IsSubclassOf(typeof(System.Security.Cryptography.HMAC)))
                throw new ArgumentException(nameof(HashAlgorithm) + "must be derived from" + typeof(System.Security.Cryptography.HMAC).FullName);

            HashBytes = hashBytes ?? throw new ArgumentNullException(nameof(hashBytes));
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// The byte array of the hash
        /// </summary>
        [NotNull]
        public byte[] HashBytes { get; }

        /// <summary>
        /// The type used to verify the bytes
        /// </summary>
        [NotNull]
        public Type HashAlgorithm { get; }

        /// <inheritdoc cref="ValueType" />
        public bool Equals(HmacRepresentative other)
        {
            return this.HashBytes.SequenceEqual(other.HashBytes) && this.HashAlgorithm == other.HashAlgorithm;
        }

        /// <inheritdoc cref="ValueType" />
        public override bool Equals(object obj)
        {
            if (obj == null) return false;
            return obj is HmacRepresentative other && Equals(other);
        }

        /// <inheritdoc cref="ValueType" />
        public override int GetHashCode()
        {
            unchecked
            {
                return (this.HashBytes.GetHashCode() * 397) ^ this.HashAlgorithm.GetHashCode();
            }
        }

        /// <inheritdoc cref="ValueType"/>
        public static bool operator ==(HmacRepresentative left, HmacRepresentative right)
        {
            return left.Equals(right);
        }

        /// <inheritdoc cref="ValueType"/>
        public static bool operator !=(HmacRepresentative left, HmacRepresentative right)
        {
            return !(left == right);
        }
    }
}
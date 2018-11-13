using System;
using System.Linq;
using FactaLogicaSoftware.CryptoTools.Digests.KeyDerivation;
using JetBrains.Annotations;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <inheritdoc cref="ValueType"/>
    /// <summary>
    /// The representation of how the key
    /// was derived for a specific transformation
    /// </summary>
    public struct KeyRepresentative : IEquatable<KeyRepresentative>
    {
        /// <inheritdoc cref="ValueType" />
        public bool Equals(KeyRepresentative other)
        {
            return this.KeyAlgorithm == other.KeyAlgorithm && this.PerformanceDerivative == other.PerformanceDerivative && this.Salt.SequenceEqual(other.Salt);
        }

        /// <inheritdoc cref="ValueType" />
        public override bool Equals(object obj)
        {
            if (obj == null) return false;
            return obj is KeyRepresentative other && Equals(other);
        }

        /// <inheritdoc cref="ValueType" />
        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = this.KeyAlgorithm.GetHashCode();
                hashCode = (hashCode * 397) ^ this.PerformanceDerivative.GetHashCode();
                hashCode = (hashCode * 397) ^ this.Salt.GetHashCode();
                return hashCode;
            }
        }

        /// <summary>
        /// The constructor for this immutable
        /// object
        /// </summary>
        /// <param name="keyAlgorithm">The algorithm used for deriving the key</param>
        /// <param name="performanceDerivative">The performance derivative used</param>
        /// <param name="salt">The salt used</param>
        public KeyRepresentative([NotNull] Type keyAlgorithm, ulong performanceDerivative, [NotNull] byte[] salt)
        {
            if (!keyAlgorithm.IsSubclassOf(typeof(KeyDerive)))
                throw new ArgumentException(nameof(KeyDerive) + "must derive from" + typeof(KeyDerive).FullName);

            this.KeyAlgorithm = keyAlgorithm;
            this.PerformanceDerivative = performanceDerivative;
            this.Salt = salt ?? throw new ArgumentNullException(nameof(salt));
        }

        /// <summary>
        /// The type used to derive the key
        /// </summary>
        [NotNull]
        public Type KeyAlgorithm { get; }

        /// <summary>
        /// The performance derivative used to generate it
        /// (See FactaLogicaSoftware.CryptoTools.PerformanceInterop)
        /// </summary>
        /// <see cref="PerformanceInterop"/>
        public ulong PerformanceDerivative { get; }

        /// <summary>
        /// The bytes of the salt used
        /// </summary>
        [NotNull]
        public byte[] Salt { get; }

        /// <inheritdoc cref="ValueType" />
        public static bool operator ==(KeyRepresentative left, KeyRepresentative right)
        {
            return left.Equals(right);
        }

        /// <inheritdoc cref="ValueType" />
        public static bool operator !=(KeyRepresentative left, KeyRepresentative right)
        {
            return !(left == right);
        }
    }
}
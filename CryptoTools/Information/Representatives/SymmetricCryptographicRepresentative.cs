using JetBrains.Annotations;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace FactaLogicaSoftware.CryptoTools.Information.Representatives
{
    /// <inheritdoc cref="CryptographicRepresentative"/>
    /// <summary>
    /// Represents how a piece of data was encrypted,
    /// including all unique instances, unlike a
    /// SymmetricCryptographicContract
    /// </summary>
    public sealed class SymmetricCryptographicRepresentative : CryptographicRepresentative, IEquatable<SymmetricCryptographicRepresentative> // Don't unseal
    {
        /// <summary>
        /// The constructor used for reading
        /// </summary>
        public SymmetricCryptographicRepresentative()
        {
            this.Type = InfoType.Read;
            this.Encoding = Encoding.UTF8;
        }
        /// <summary>
        /// The constructor used for reading,
        /// taking the file path to read the values from
        /// </summary>
        public SymmetricCryptographicRepresentative(string filePath)
        {
            this.Type = InfoType.Read;
            this.Encoding = Encoding.UTF8;
            this.ReadHeaderFromFile(filePath);
        }

        /// <summary>
        /// The constructor for creating an object used for writing
        /// or information
        /// </summary>
        [JsonConstructor]
        public SymmetricCryptographicRepresentative(TransformationRepresentative transformationModeInfo, KeyRepresentative? instanceKeyCreator = null, HmacRepresentative? hmacRepresentative = null)
        {
            this.Type = InfoType.Write;
            this.TransformationModeInfo = transformationModeInfo;
            this.InstanceKeyCreator = instanceKeyCreator;
            this.HmacRepresentative = hmacRepresentative;
            this.Encoding = Encoding.UTF8;
        }

        /// <summary>
        /// The representation of the HMAC
        /// authenticator for a piece of data
        /// </summary>
        [CanBeNull]
        public HmacRepresentative? HmacRepresentative { get; private set; }

        /// <summary>
        /// The representation of the encryption
        /// of certain data
        /// </summary>
        public TransformationRepresentative TransformationModeInfo { get; private set; }

        /// <summary>
        /// The representation of how to derive the key
        /// for a certain piece of data
        /// </summary>
        [CanBeNull]
        public KeyRepresentative? InstanceKeyCreator { get; private set; }

        /// <inheritdoc />
        /// <summary>
        /// Create the JSON data for the current object
        /// </summary>
        /// <returns>The string of JSON data</returns>
        public override string GenerateHeader()
        {
            return JsonConvert.SerializeObject(this);
        }

        /// <inheritdoc />
        /// <summary>
        /// Read a header from a string and return the object
        /// </summary>
        /// <param name="header">The string of header DATA</param>
        /// <returns>The cryptographic info object created from the data</returns>
        public override void ReadHeader(string header)
        {
            // Get the index of the start and end of the JSON object

            int start = header.IndexOf(StartChars, StringComparison.Ordinal) + StartChars.Length; // + StartChars.Length, IndexOf gets the first character of the string search, so adding the length pushes it to the end of that
            int end = header.IndexOf(EndChars, StringComparison.Ordinal);

            // If either search failed and returned -1, fail, as the header is corrupted
            if (start == -1 || end == -1)
            {
                throw new FileFormatException("Start or end validation strings corrupted");
            }

            // Get the data between the indexes : that's why we added the length of StartChars earlier
            string jsonString = header.Substring(start, end - start);

            // Set the length of the header read
            this.HeaderLength = StartChars.Length + jsonString.Length + EndChars.Length;

            SymmetricCryptographicRepresentative data;

            try
            {
                // Create the data deserialized to a cryptographic object
                data = JsonConvert.DeserializeObject<SymmetricCryptographicRepresentative>(jsonString);
            }
            catch (JsonException)
            {
                throw new ArgumentException("String should not contain BOM");
            }

            // Don't use reflection please, it's slow :)
            this.InstanceKeyCreator = data.InstanceKeyCreator;
            this.HmacRepresentative = data.HmacRepresentative;
            this.TransformationModeInfo = data.TransformationModeInfo;
            this.Type = InfoType.Read;
            this.HeaderLength = data.HeaderLength;
            this.Encoding = data.Encoding;
        }

        /// <inheritdoc />
        /// <summary>
        /// Read a header and return the object created from it
        /// </summary>
        /// <param name="path">The file path to read rom</param>
        /// <returns>The cryptographic info object created from the file data</returns>
        public override void ReadHeaderFromFile(string path)
        {
            // Create the streams needed to read from the file
            var fileStream = new FileStream(path, FileMode.Open);
            using (var binReader = new BinaryReader(fileStream, this.Encoding ?? Encoding.UTF8))
            {
                // The header limit is 5KB, so read that and we know we have it all
                string header;

                int toReadVal = 1024 * 3;

                while (true)
                {
                    try
                    {
                        header = Encoding.UTF8.GetString(binReader.ReadBytes(toReadVal));
                        break;
                    }
                    catch (ArgumentException)
                    {
                        toReadVal++;
                    }
                }

                // Get the index of the start and end of the JSON object
                int start = header.IndexOf("BEGIN ENCRYPTION HEADER STRING", StringComparison.Ordinal) + StartChars.Length; // + StartChars.Length, IndexOf gets the first character of the string search, so adding the length pushes it to the end of that
                int end = header.IndexOf("END ENCRYPTION HEADER STRING", StringComparison.Ordinal);

                // If either search failed and returned -1, fail, as the header is corrupted
                if (start == -1 || end == -1)
                {
                    throw new FileFormatException($"{(start == -1 ? "Start" : "End")} validation string corrupted");
                }

                // Get the data between the indexes : that's why we added the length of StartChars earlier
                string jsonString = header.Substring(start, end - start);

                binReader.BaseStream.Seek(0, SeekOrigin.Begin);
                byte[] byteOrderMark = binReader.ReadBytes(3);

                byte byteOrderMarkLength = 0;

                if (byteOrderMark.SequenceEqual(new byte[] { 0xEF, 0xBB, 0xBF }))
                {
#if DEBUG
                    Console.WriteLine("File has UTF8 3-byte BOM");
#endif
                    byteOrderMarkLength = 3;
                }
                else
                {
#if DEBUG
                    Console.WriteLine("File has no BOM");
#endif
                }

                // Set the length of the header read
                this.HeaderLength = StartChars.Length + jsonString.Length + EndChars.Length
                                    + byteOrderMarkLength; // 3 is length of BOM

                // Create the data deserialized to a cryptographic object
                var deserializeObject = JsonConvert.DeserializeObject<SymmetricCryptographicRepresentative>(jsonString);
                deserializeObject.Type = InfoType.Read;
                
                // Don't use reflection please, it's slow :)
                this.InstanceKeyCreator = deserializeObject.InstanceKeyCreator;
                this.HmacRepresentative = deserializeObject.HmacRepresentative;
                this.TransformationModeInfo = deserializeObject.TransformationModeInfo;
                this.Type = InfoType.Read;
                this.HeaderLength = deserializeObject.HeaderLength;
                this.Encoding = deserializeObject.Encoding;
            }
        }

        /// <inheritdoc />
        /// <summary>
        /// Writes the current version of the write object to a file
        /// </summary>
        /// <param name="path">The file path to write to</param>
        public override void WriteHeaderToFile(string path)
        {
            // Create the JSON representative of the JSON object
            string json = JsonConvert.SerializeObject(this, Formatting.Indented);

            // Create a stream to overwrite the path file to write the header file and a StreamWriter to write
            var writeFileStream = new FileStream(path, FileMode.Create);
            using (var writer = new StreamWriter(writeFileStream, this.Encoding))
            {
                // Write the data
                writer.Write(StartChars);
                writer.Write(json);
                writer.Write(EndChars);
            }

            // Define the length of the header
            this.HeaderLength = StartChars.Length + json.Length + EndChars.Length;
        }

        /// <inheritdoc />
        /// <summary>
        /// Compares the 2 objects for reference
        /// OR value equality
        /// </summary>
        /// <param name="other">The other object to test</param>
        /// <returns></returns>
        public bool Equals(SymmetricCryptographicRepresentative other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return this.HmacRepresentative == other.HmacRepresentative && this.TransformationModeInfo == other.TransformationModeInfo && this.InstanceKeyCreator == other.InstanceKeyCreator;
        }

        /// <inheritdoc />
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj.GetType() == this.GetType() && Equals((SymmetricCryptographicRepresentative)obj);
        }

        /// <inheritdoc />
        public override int GetHashCode()
        {
            return 0;
        }

        /// <inheritdoc cref="IEquatable{T}"/>
        public static bool operator ==(SymmetricCryptographicRepresentative left,
            SymmetricCryptographicRepresentative right)
        {
            return left?.Equals(right) ?? false;
        }

        /// <inheritdoc cref="IEquatable{T}"/>
        public static bool operator !=(SymmetricCryptographicRepresentative left, SymmetricCryptographicRepresentative right)
        {
            return !(left == right);
        }
    }
}
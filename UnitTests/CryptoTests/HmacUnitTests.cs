using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using FactaLogicaSoftware.CryptoTools.HMAC;
using Xunit;
// ReSharper disable StringLiteralTypo

namespace UnitTests.CryptoTests
{
    public class HmacUnitTests
    {
        [Theory]
        [ClassData(typeof(HmacTestData))]
        public void MixedDataTest(byte[] testBytes, byte[] key)
        {
            byte[] hashedBytes = MessageAuthenticator.CreateHmac(testBytes, key);

            Assert.True(MessageAuthenticator.VerifyHmac(testBytes, key, hashedBytes));
        }

    }

    public class HmacTestData : IEnumerable<object[]>
    {
        public IEnumerator<object[]> GetEnumerator()
        {
            var constantTestKey = new byte[64];
            var rng = new Random();
            rng.NextBytes(constantTestKey);

            yield return new object[] { Encoding.UTF8.GetBytes("Hello! This is the easy test :)"), constantTestKey };
            yield return new object[] { Encoding.UTF8.GetBytes("asfjgijuor;aegud;askgdiubjoiaebj"), constantTestKey };

            var bigData = new byte[1024 * 1024];
            rng.NextBytes(bigData);

            yield return new object[] { bigData, constantTestKey };

            Array.Clear(bigData, 0, bigData.Length);

            yield return new object[] { bigData, constantTestKey };
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}

using System;
using System.Runtime.InteropServices;

namespace FactaLogicaSoftware.CryptoTools.SecureMemory
{
    /// <summary>
    /// Provides a set of static methods for working with memory
    /// </summary>
    public static unsafe class SecureMemoryMarshal
    {
        /// <summary>
        /// Zeroes a certain block of memory using unsafe code
        /// </summary>
        /// <param name="start">The pointer to the block to zero</param>
        /// <param name="length">How many bytes to zero</param>
        public static void SecureDestroyMemory(void* start, long length)
        {
            for (var i = 0L; i < length; i++)
            {
                if (length - i < 8)
                {
                    *((long*) start + i) = 0b_0000_0000;
                    i += 7;
                }
                else
                    *((byte*)start + i) = 0b_0000_0000;
            }

        }

        /// <summary>
        /// Zeroes an unmanaged struct using unsafe code
        /// </summary>
        /// <typeparam name="T">The unmanaged struct type</typeparam>
        /// <param name="dataStructure">The unmanaged struct to zero</param>
        public static void SecureDestroyMemory<T>(T dataStructure) where T : unmanaged
        {
            GCHandle handle = GCHandle.Alloc(dataStructure, GCHandleType.Pinned);
            try
            {
                SecureDestroyMemory(handle.AddrOfPinnedObject().ToPointer(), sizeof(T));
            }
            finally
            {
                handle.Free();

            }
        }
    }
}

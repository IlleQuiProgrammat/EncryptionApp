using System;
using System.Runtime.InteropServices;

namespace FactaLogicaSoftware.CryptoTools.SecureMemory
{
    /// <summary>
    /// TODO
    /// </summary>
    public static unsafe class SecureMemoryMarshal
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="start"></param>
        /// <param name="length"></param>
        public static void SecureDestroyMemory(void* start, long length)
        {
            for (var i = 0L; i < length; i++)
            {
                if (length - i < 8)
                    *((long*)start + i) = 0;
                else
                    *((byte*)start + i) = 0;
            }

        }

        /// <summary>
        /// TODO
        /// </summary>
        public static void SecureDestroyMemory<T>(T dataStructure) where T : unmanaged
        {
            GCHandle handle = GCHandle.Alloc(dataStructure, GCHandleType.Pinned);
            SecureDestroyMemory(handle.AddrOfPinnedObject().ToPointer(), sizeof(T));
            handle.Free();
        }
    }
}

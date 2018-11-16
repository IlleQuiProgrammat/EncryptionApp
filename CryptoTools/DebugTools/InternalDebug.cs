#if DEBUG

namespace FactaLogicaSoftware.CryptoTools.DebugTools
{
    using System;
    using System.Globalization;
    using System.IO;

    /// <summary>
    /// A set of statics for debugging
    /// </summary>
    public static class InternalDebug
    {
        private const string LogDirectoryPath = @"CryptoTools\Debug\";

        private static readonly object LockForFileExclusivity = new object();

        /// <summary>
        /// Writes a set of strings to
        /// the diagnostics file
        /// </summary>
        /// <param name="items">The strings to write</param>
        public static void WriteToDiagnosticsFile(params object[] items)
        {
            lock (LockForFileExclusivity)
            {
                if (!Directory.Exists(LogDirectoryPath))
                {
                    Directory.CreateDirectory(LogDirectoryPath);
                }

                if (!File.Exists(LogDirectoryPath + "Log.txt"))
                {
                    File.Create(LogDirectoryPath + "DiagnosticsAndDebug.data");
                }

                using (var fileWriter = new StreamWriter(new FileStream(LogDirectoryPath + "Log.txt", FileMode.Append)))
                {
                    fileWriter.WriteLine('\n' + DateTime.Now.ToString(CultureInfo.CurrentCulture));
                    foreach (object item in items)
                    {
                        switch (item)
                        {
                            case Exception exceptionCastedItem:
                                fileWriter.WriteLine("Exception thrown: " + exceptionCastedItem);
                                break;

                            case string stringCastedItem:
                                fileWriter.WriteLine(stringCastedItem);
                                break;

                            default:
                                fileWriter.WriteLine(item.ToString());
                                break;
                        }
                    }
                }
            }
        }
    }
}

#endif
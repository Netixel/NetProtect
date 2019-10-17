using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetProtect.Internal
{
    internal enum Protection
    {
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_GUARD = 0x100,
        PAGE_NOCACHE = 0x200,
        PAGE_WRITECOMBINE = 0x400
    }
    internal class Win32
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, Protection flNewProtect, out Protection lpflOldProtect);

        [DllImport("kernel32.dll",
            EntryPoint = "GetStdHandle",
            SetLastError = true,
            CharSet = CharSet.Auto,
            CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr GetStdHandle(int nStdHandle);
        [DllImport("kernel32.dll",
            EntryPoint = "AllocConsole",
            SetLastError = true,
            CharSet = CharSet.Auto,
            CallingConvention = CallingConvention.StdCall)]
        internal static extern int AllocConsole();
        internal const int STD_OUTPUT_HANDLE = -11;
        internal const int MY_CODE_PAGE = 437;

        private static bool IsAlloc = false;
        internal static void AllocConsoleOnce()
        {
#if DEBUG
            if (!IsAlloc)
            {
                IsAlloc = true;
                AllocConsole();
                IntPtr stdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
                SafeFileHandle safeFileHandle = new SafeFileHandle(stdHandle, true);
                FileStream fileStream = new FileStream(safeFileHandle, FileAccess.Write);
                Encoding encoding = System.Text.Encoding.GetEncoding(MY_CODE_PAGE);
                StreamWriter standardOutput = new StreamWriter(fileStream, encoding);
                standardOutput.AutoFlush = true;
                Console.SetOut(standardOutput);
            }
#endif
        }
        internal static void Print(string message)
        {
#if DEBUG
            AllocConsoleOnce();
            LoggingExtensions.WriteDebug(message); //safe way to log to debug.txt
            if(Console.Out != null)
                Console.WriteLine(message);
#endif
        }
    }

    internal static class LoggingExtensions
    {
        static ReaderWriterLock locker = new ReaderWriterLock();
        internal static void WriteDebug(this string text)
        {
#if DEBUG
            try
            {
                locker.AcquireWriterLock(int.MaxValue); //You might wanna change timeout value 
                System.IO.File.AppendAllLines(Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().GetName().CodeBase).Replace("file:\\", ""), "debug.txt"), new[] { text });
            }
            finally
            {
                locker.ReleaseWriterLock();
            }
#endif
        }
    }
}

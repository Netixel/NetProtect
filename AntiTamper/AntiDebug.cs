using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace NetProtect.AntiTamper
{
    class AntiDebug
    {
        [MethodHash("uncomputed")]
        public static bool DetectDebuggers()
        {
            if (DotNetDebugger())
                return true;
            if (IsDebuggerPresent())
                return true;
            if (ProcessNames())
                return true;
            if (WindowTitles())
                return true;
            if (IsRemoteDebugger())
                return true;
            if (ThreadContextCheck())
                return true;

            return false;
        }
        [MethodHash("uncomputed")]
        public static void StartForceBreak()
        {
            Thread t = new Thread(() =>
            {
                while(true)
                {
                    Debugger.Break();
                    DebugBreak();
                    AsmBreak();
                    Thread.Sleep(10);
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        //no method hash here because we are going to replace it on compile

        private static void DebugBreak()
#warning No handling of DebugBreak in compiler
        {
            Debugger.Break();
        }
        //no method hash here because we are going to replace it on compile
        private static void AsmBreak()
#warning No handling of AsmBreak in compiler
        {
            Debugger.Break();
        }

        [MethodHash("uncomputed")]
        private static bool ThreadContextCheck()
        {
            CONTEXT64 ctx = new CONTEXT64();
            ctx.ContextFlags = CONTEXT_FLAGS.CONTEXT_DEBUG_REGISTERS;
            if(GetThreadContext(GetCurrentThread(), ref ctx))
            {
                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
                {
                    return true;
                }
            }
            return false;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);


        [StructLayout(LayoutKind.Sequential)]
        public struct M128A
        {
            public ulong High;
            public long Low;

            public override string ToString()
            {
                return string.Format("High:{0}, Low:{1}", this.High, this.Low);
            }
        }
        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct XSAVE_FORMAT64
        {
            public ushort ControlWord;
            public ushort StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public ushort ErrorOpcode;
            public uint ErrorOffset;
            public ushort ErrorSelector;
            public ushort Reserved2;
            public uint DataOffset;
            public ushort DataSelector;
            public ushort Reserved3;
            public uint MxCsr;
            public uint MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }

        private enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
            CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;

            public XSAVE_FORMAT64 DUMMYUNIONNAME;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }
        [MethodHash("uncomputed")]
        private static bool IsRemoteDebugger()
        {
            bool result = false;
            if (CheckRemoteDebuggerPresent(Process.GetCurrentProcess().SafeHandle, ref result))
            {
                if (result)
                    return true;
            }
            return false;
        }

        [DllImport("Kernel32.dll", SetLastError = true, ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CheckRemoteDebuggerPresent(SafeHandle hProcess, [MarshalAs(UnmanagedType.Bool)]ref bool isDebuggerPresent);

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();
        [MethodHash("uncomputed")]
        private static bool DotNetDebugger()
        {
            return Debugger.IsAttached;
        }
        [MethodHash("uncomputed")]
        private static bool ProcessNames()
        {
            string[] bad_proc_names = new string[] { "dnspy" };

            foreach (string name in bad_proc_names)
            {
                if (Process.GetProcessesByName(name).Length > 0)
                    return true;
            }

            return false;
        }
        [MethodHash("uncomputed")]
        private static bool WindowTitles()
        {
            string[] bad_window_names = new string[] { "dnspy", "cheat engine" };

            foreach (Process p in Process.GetProcesses())
            {
                foreach (string name in bad_window_names)
                {
                    if (p.MainWindowTitle.ToLower().Contains(name))
                        return true;
                }
            }
            return false;
        }
    }
}

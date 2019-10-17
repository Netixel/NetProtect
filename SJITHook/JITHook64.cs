/*The MIT License (MIT)

Copyright (c) 2014 UbbeLoL

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.*/

using NetProtect.AntiTamper;
using NetProtect.Internal;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace SJITHook
{
    public unsafe class JITHook64<T> where T : VTableAddrProvider
    {
        private readonly T _addrProvider;
        public Data.CompileMethodDel64 OriginalCompileMethod { get; private set; }
        public Data.CompileMethodDel64 NewCompileMethod { get; private set; } //this solves Delegate garbage collection issues

        public JITHook64()
        {
            _addrProvider = Activator.CreateInstance<T>();
        }

        private unsafe void PrintPointer(IntPtr ptr)
        {
            long* address = (long*)ptr.ToPointer();
            long value = *address;

            Win32.Print($"Original Compile: 0x{value.ToString("x8")}");
        }


        private void ProtectVTable()
        {
            while(true)
            {
                IntPtr pVTable = _addrProvider.VTableAddr;
                IntPtr pCompileMethod = Marshal.ReadIntPtr(pVTable);

                IntPtr desired_value = Marshal.GetFunctionPointerForDelegate(NewCompileMethod);

                IntPtr actual_value = Marshal.ReadIntPtr(pCompileMethod);

                if(actual_value != desired_value)
                {
                    Win32.Print("vTable Hook Broken!");
                    SafeCrash.ForceCrash();
                }


                byte[] required_bytes = new byte[]
                {
                    0x48 ,0x8B ,0xC4 ,0x48 ,0x89 ,0x58 ,0x08 ,0x48 ,0x89 ,0x68 ,0x10 ,0x48 ,0x89 ,0x70 ,0x18 ,0x48 ,0x89 ,0x78 ,0x20 ,0x41 ,0x56 ,0x48 ,0x83 ,0xEC ,0x60 ,0x48 ,0x8B ,0x3D
                };
                IntPtr og_address = Marshal.GetFunctionPointerForDelegate(OriginalCompileMethod);

                for (int i = 0; i < required_bytes.Length;i++)
                {
                    byte og_byte = Marshal.ReadByte(og_address + i);
                    if (og_byte != required_bytes[i])
                    {
                        Win32.Print("Modified ClrJit! Likely hooked!");
                        SafeCrash.ForceCrash();
                    }
                }

                System.Threading.Thread.Sleep(100);
            }
        }



        public bool Hook(Data.CompileMethodDel64 hookedCompileMethod)
        {
            this.NewCompileMethod = hookedCompileMethod;
            IntPtr pVTable = _addrProvider.VTableAddr;
            IntPtr pCompileMethod = Marshal.ReadIntPtr(pVTable);
            uint old;

            if (
                !Data.VirtualProtect(pCompileMethod, (uint)IntPtr.Size,
                    Data.Protection.PAGE_EXECUTE_READWRITE, out old))
                return false;

            OriginalCompileMethod =
                (Data.CompileMethodDel64)
                    Marshal.GetDelegateForFunctionPointer(Marshal.ReadIntPtr(pCompileMethod), typeof (Data.CompileMethodDel64));

            PrintPointer(pCompileMethod);


            // We don't want any infinite loops :-)
            RuntimeHelpers.PrepareDelegate(NewCompileMethod);
            RuntimeHelpers.PrepareDelegate(OriginalCompileMethod);
            RuntimeHelpers.PrepareMethod(GetType().GetMethod("ProtectVTable", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).MethodHandle, new[] { typeof(T).TypeHandle });
            RuntimeHelpers.PrepareMethod(GetType().GetMethod("UnHook").MethodHandle, new[] {typeof (T).TypeHandle});

            Marshal.WriteIntPtr(pCompileMethod, Marshal.GetFunctionPointerForDelegate(NewCompileMethod));

            System.Threading.Thread vTableVerifier = new System.Threading.Thread(() => ProtectVTable());
            vTableVerifier.IsBackground = true;
            vTableVerifier.Start();


            return Data.VirtualProtect(pCompileMethod, (uint)IntPtr.Size,
                Data.Protection.PAGE_EXECUTE_READ, out old);
        }

        public bool UnHook()
        {
            IntPtr pVTable = _addrProvider.VTableAddr;
            IntPtr pCompileMethod = Marshal.ReadIntPtr(pVTable);
            uint old;

            if (
                !Data.VirtualProtect(pCompileMethod, (uint)IntPtr.Size,
                    Data.Protection.PAGE_EXECUTE_READWRITE, out old))
                return false;

            Marshal.WriteIntPtr(pCompileMethod, Marshal.GetFunctionPointerForDelegate(OriginalCompileMethod));

            return Data.VirtualProtect(pCompileMethod, (uint)IntPtr.Size,
                (Data.Protection) old, out old);
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using NetProtect.Extensibles;
using NetProtect.Internal;
using SJITHook;
using NetProtect.AntiTamper;
using NetProtect.Methods;
using System.Runtime.CompilerServices;

namespace NetProtect
{
    /*
     
         
         Project notes:

         We have two attributes
            ClrEncrypted(EncryptionType type, bool IsStreamed)
            MethodHash(string hash)
         
         On compile we need to know
            1. Is this encrypted?
            2. Is this hashed?
         
         If it is encrypted we need to 
            1. Locate the encrypted source (embed or streamed)
            2. Decrypte the source (encryption type)
            2. Replace existing MSIL with decrypted MSIL
         
         If it is hashed we need to
            1. Compute a hash of the MSIL before compilation
            2. Verify that hash matches what we expect


         Anti-debugging
            1. When we do crash (or know an issue has occured ), we need to crash on a new thread (SafeCrash handles this)
            2. We need to verify there is not debugger present every time a method is compiled (specifically encrypted methods)
            3. We need to verify the internal hash check has not been manipulated (we need a static hash calculated for our hash check alg)
            4. Use MSIL/ASM software & hardware breakpoints on another thread
            5. Use system time to verify the software/hardware breakpoints were not triggered
            
        


        === We need to clean this project up, make it a bit more formal & logical with its methods and classes ===

        === We need to rebuild our encrypter so our method hashes can be inserted ===


         */

    public class JitEncrypt
    {
        private JITHook64<ClrjitAddrProvider> _jitHook64;

        private Dictionary<long, JitMethodBase> EncryptedMethods;
        private Dictionary<long, JitMethodBase> HashedMethods;

        /// <summary>
        /// Constructs the JitEncrypt Client Library
        /// </summary>
        /// <param name="remote_url">URL for retrieving remote functions</param>
        public JitEncrypt(string remote_url = "")
        {
            EncryptedMethod.DOWNLOAD_URL = remote_url;

            EncryptedMethods = new Dictionary<long, JitMethodBase>();
            HashedMethods = new Dictionary<long, JitMethodBase>();
            _jitHook64 = new JITHook64<ClrjitAddrProvider>();


            Win32.Print("Mapping methods...");
            DetectMethods();
        }

        public void SetDecryptionKey(string key)
        {
            EncryptedMethod.DecryptionKey = key;
        }

        public unsafe void Enable()
        {
            PreJit();
            //--- TODO: check MD5 of the assembly

            if (!_jitHook64.Hook(ClrCompile64))
            {
                throw new Exception("Hook failed!");
            }

            AntiDebug.StartForceBreak();
        }
        public unsafe void Disable()
        {
            _jitHook64.UnHook();

            #warning AntiDebug needs to stop its force break loop started in the Enable() function
        }


        //Method dection & list mapping
        private unsafe void DetectMethods()
        {
            foreach (Assembly asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                foreach (Module module in asm.GetModules())
                {
                    IntPtr m_ptrDataValue = module.GetHMODULE();
                    if (m_ptrDataValue == null)
                    {
                        Win32.Print($"Module: {module.Name} has no handle!");
                        continue;
                    }


                    foreach (MethodInfo method in module.GetMethods())
                    {
                        MapMethod(method, m_ptrDataValue, module);
                    }
                    foreach (Type typeDef in module.GetTypes())
                    {
                        foreach (MethodInfo method in typeDef.GetRuntimeMethods())
                        {
                            MapMethod(method, m_ptrDataValue, module);
                        }
                    }
                }
            }
        }
        private unsafe void MapMethod(MethodInfo method, IntPtr HMODULE, Module module)
        {
            ClrEncrypted encryption = method.GetCustomAttribute<ClrEncrypted>(false);
            if (encryption != null)
            {
                int token = method.MetadataToken;
                JitMethodBase entry = new EncryptedMethod(HMODULE, token, method, encryption);
                EncryptedMethods.Add(entry.Token + entry.hMODULE.ToInt64(),entry);
                Win32.Print($"Encrypted: {module.Name}::{method.Name} [0x{token.ToString("x8")}] with method: {Enum.GetName(typeof(EncryptionType), encryption.Type)} | Streamed? {encryption.Streamed}");
            }

            MethodHash hash = method.GetCustomAttribute<MethodHash>(false);
            if (hash != null)
            {
                int token = method.MetadataToken;
                JitMethodBase entry = new HashedMethod(HMODULE, token, method, hash);
                HashedMethods.Add(entry.Token + entry.hMODULE.ToInt64(), entry);
                Win32.Print($"Hashed: {module.Name}::{method.Name} [0x{token.ToString("x8")}] Value: {hash.Hash}");
            }
        }

        //delegate preperation & JIT Stack fixes
        private unsafe void PreJit()
        {
            Win32.Print("PreJIT: FindMatchingMethods");
            MethodInfo method = typeof(JitEncrypt).GetMethod("FindMethods", BindingFlags.Instance | BindingFlags.NonPublic);
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            Win32.Print("PreJIT: ContainsKey");
            method = typeof(Dictionary<long, JitMethodBase>).GetMethod("ContainsKey", BindingFlags.Instance | BindingFlags.Public);
            RuntimeHelpers.PrepareMethod(method.MethodHandle);

            Win32.Print("PreJIT: FindMatchingMethods [Call]");
            //--- Note the following requests are required to prevent stack overflow exceptions on some deep .net methods that they call
            Data.CorMethodInfo64 methodInfo = new Data.CorMethodInfo64() //--- create fake data structure pointing to our fake method
            {
                moduleHandle = new IntPtr(int.MaxValue),
                methodHandle = new IntPtr(int.MaxValue - 0x06000000)
            };
            JitMethodBase temp = new JitMethodBase(methodInfo.moduleHandle, int.MaxValue, method, new ClrEncrypted(EncryptionType.aes, false)); //--- define our fake method
            JitMethodBase temp2 = new JitMethodBase(methodInfo.moduleHandle, int.MaxValue, method, new MethodHash("fake method hash")); //--- define our fake method
            long value = temp.hMODULE.ToInt64() + temp.Token;//--- calculate our fake method's lookup token
            EncryptedMethods.Add(value, temp);//--- add our fake method to our dictioanry
            HashedMethods.Add(value, temp2);
            FindMethods(&methodInfo); // use FindMethods to PreJit the entire chain
            EncryptedMethods.Clear();  //--- clear our dictionary of our fake method to prevent issues
            HashedMethods.Clear();

            if (AntiDebug.DetectDebuggers())
            {
                Win32.Print("Debugger Present");
                SafeCrash.ForceCrash();
            }

        }

        private unsafe JitMethodBase[] FindMethods(Data.CorMethodInfo64* methodInfo)
        {
            if (methodInfo->methodHandle == IntPtr.Zero)
                return new JitMethodBase[0];

            //--- quickly check if this method exists in our dictionarys & if it does add it to be returned
            long value = methodInfo->moduleHandle.ToInt64() + (0x06000000 + *(ushort*)methodInfo->methodHandle);
            List<JitMethodBase> methods = new List<JitMethodBase>();
            if (EncryptedMethods.ContainsKey(value))
            {
                methods.Add(EncryptedMethods[value]);
            }
            if(HashedMethods.ContainsKey(value))
            {
                methods.Add(HashedMethods[value]);
            }

            return methods.ToArray(); 

        }


        private unsafe void HandleCompile(JitMethodBase method_base, Data.CorMethodInfo64* methodInfo)
        {
            
            var msil_bytes = new byte[methodInfo->ilCodeSize];
            Marshal.Copy(methodInfo->ilCode, msil_bytes, 0, msil_bytes.Length);
            

            if (method_base is EncryptedMethod ecr_method) //encrypted method
            {
                Win32.Print("\tOriginal: " + BitConverter.ToString(msil_bytes));

                //virtual protect --- we are about to write to this location
                if (!Win32.VirtualProtect(methodInfo->ilCode, methodInfo->ilCodeSize, Protection.PAGE_EXECUTE_READWRITE, out Protection old_protect))
                {
                    Win32.Print("VirtualProtect #1 Failed");
                    SafeCrash.ForceCrash();
                }

                byte[] new_bytes = ecr_method.Decrypt(); //--- decrypt our method

                if (new_bytes.Length == 0)
                {
                    Win32.Print("New bytes length = 0");
                    SafeCrash.ForceCrash();
                }

                Win32.Print("Decrypted: " + BitConverter.ToString(new_bytes));

                // write our decrypted bytes
                for (uint i = 0; i < methodInfo->ilCodeSize; i++)
                {
                    byte* address = ((byte*)methodInfo->ilCode) + i;
                    *address = new_bytes[i];
                }

                //wipe our decrypte bytes from the stack
                Array.Clear(new_bytes, 0, new_bytes.Length);


                //virtual protect --- we are done writing so restore our protection
                if (!Win32.VirtualProtect(methodInfo->ilCode, methodInfo->ilCodeSize, old_protect, out Protection ignore))
                {
                    Win32.Print("VirtualProtect #2 failed");
                    SafeCrash.ForceCrash();
                }

            }
            else if (method_base is HashedMethod hsh_method)
            {
                //hashed method --- verify integrity
                hsh_method.VerifyHash(msil_bytes);
            }
            else
            {
                Win32.Print("Unknown Method Type");
                SafeCrash.ForceCrash(); //Not definitive type, crash us
            }
        }



        private unsafe int ClrCompile64(IntPtr thisPtr, [In] IntPtr corJitInfo,
            [In] Data.CorMethodInfo64* methodInfo, Data.CorJitFlag flags,
            [Out] IntPtr nativeEntry, [Out] IntPtr nativeSizeOfCode)
        {
            JitMethodBase[] compiling_methods = FindMethods(methodInfo);

            //IntPtr corJitInfo_vTable = Marshal.ReadIntPtr(corJitInfo);

            if (compiling_methods.Length != 0)
            {
                //detect debuggers
                if (AntiDebug.DetectDebuggers())
                {
                    Win32.Print("On Compile - Debugger Present");
                    SafeCrash.ForceCrash();
                }

                JitMethodBase method_base = compiling_methods[0];
                Win32.Print($"Compiling: {method_base.Method.Name}");


                if (compiling_methods.Length == 1)
                {
                    //--- one matching method, HandleCompile we determine what to do
                    HandleCompile(method_base, methodInfo);
                }
                else
                {
                    //--- two matching methods, must handle decryption before hashing
                    foreach (JitMethodBase method in compiling_methods)
                    {
                        if (method is EncryptedMethod encrypted)
                        {

                            HandleCompile(encrypted, methodInfo);
                            break;
                        }
                    }
                    foreach (JitMethodBase method in compiling_methods)
                    {
                        if (method is HashedMethod hashed)
                        {
                            HandleCompile(hashed, methodInfo);
                            break;
                        }
                    }
                }

            }

            return _jitHook64.OriginalCompileMethod(thisPtr, corJitInfo, methodInfo, flags, nativeEntry, nativeSizeOfCode);
        }
    }
}

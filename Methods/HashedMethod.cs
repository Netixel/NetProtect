using NetProtect.AntiTamper;
using NetProtect.Internal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetProtect.Methods
{
    class HashedMethod : JitMethodBase
    {
        public HashedMethod(IntPtr hMODULE, int token, MethodInfo method, MethodHash hash) : base(hMODULE,token,method,hash)
        {
        }
        public MethodHash Hashed {
            get {
                return (MethodHash)this.MethodAttribute;
            }
        }

        public void VerifyHash(byte[] compiling_msil)
        {
            string computed = "";
            using (MD5 md5 = MD5.Create())
            {
                byte[] result = md5.ComputeHash(compiling_msil);
                StringBuilder sb = new StringBuilder();

                for (int i = 0; i < result.Length; i++)
                {
                    sb.Append(result[i].ToString("X2"));
                }
                computed = sb.ToString();
            }
            if (computed != this.Hashed.Hash)
            {
                Win32.Print($"Mismatch Hash (computed/expected): {computed} vs {this.Hashed.Hash}");
                SafeCrash.ForceCrash();
            }
        }
    }
}

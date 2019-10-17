using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace NetProtect.Methods
{
    class JitMethodBase
    {
        public JitMethodBase(IntPtr hMODULE, int Token, MethodInfo Method, Attribute MethodAttribute)
        {
            this.hMODULE = hMODULE;
            this.Token = Token;
            this.Method = Method;
            this.MethodAttribute = MethodAttribute;
        }

        public IntPtr hMODULE { get; set; }
        public int Token { get; set; }
        public MethodInfo Method { get; set; }
        public Attribute MethodAttribute { get; set; }

        public unsafe bool DoesMatch(IntPtr ModuleHandle, ushort methodHandle)
        {
            bool module = HandleMatch(ModuleHandle);
            bool token = TokenMatch(0x06000000 + methodHandle);
            return module && token;
        }
        protected unsafe bool HandleMatch(IntPtr ModuleHandle)
        {
            return this.hMODULE == ModuleHandle;
        }
        protected unsafe bool TokenMatch(int tokenIdentifier)
        {
            return this.Token == tokenIdentifier;
        }
    }
}

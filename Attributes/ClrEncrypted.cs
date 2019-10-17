using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetProtect
{
    public enum EncryptionType
    {
        xor,
        aes,
        rsa,
    }
    public class ClrEncrypted : Attribute
    {
        /// <summary>
        /// NetProtect Encrypted Method Flag
        /// </summary>
        /// <param name="_type">Encryption type to apply to this method</param>
        /// <param name="_streamed">Is this method streamed from a remote source</param>
        public ClrEncrypted(EncryptionType _type, bool _streamed)
        {
            this.Type = _type;
            this.Streamed = _streamed;
        }
        public EncryptionType Type;
        public bool Streamed;
    }
}

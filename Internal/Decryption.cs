using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace NetProtect.Internal
{
    internal class Decryption
    {
        internal static byte[] DecryptAES(byte[] RVAR19, string RVAR20)
        {
            RijndaelManaged AES = new System.Security.Cryptography.RijndaelManaged();
            byte[] hash = new byte[32];
            byte[] temp = new MD5CryptoServiceProvider().ComputeHash(System.Text.Encoding.ASCII.GetBytes(RVAR20));
            Array.Copy(temp, 0, hash, 0, 16);
            Array.Copy(temp, 0, hash, 15, 16);
            AES.Key = hash;
            AES.Mode = CipherMode.ECB;
            ICryptoTransform DESDecrypter = AES.CreateDecryptor();
            byte[] decrypted = DESDecrypter.TransformFinalBlock(RVAR19, 0, RVAR19.Length);
            return decrypted;
        }
        internal static byte[] DecrypteXOR(byte[] bytes, byte xor_byte)
        {
            for(int i = 0; i < bytes.Length;i++)
            {
                bytes[i] ^= xor_byte;
            }
            return bytes;
        }

        internal static byte[] DecryptRSA(byte[] bytes, byte[] key)
        {
            return new byte[0];
        }

    }
}

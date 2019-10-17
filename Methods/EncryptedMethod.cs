using NetProtect.Internal;
using SJITHook;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace NetProtect.Methods
{
    class EncryptedMethod : JitMethodBase
    {
        public static string DOWNLOAD_URL = "";


        private static string DecryptionKey = "";

        public EncryptedMethod(IntPtr hMODULE, int token, MethodInfo method, ClrEncrypted encryption) : base(hMODULE, token, method, encryption)
        {
        }
        public ClrEncrypted Encryption {
            get {
                return (ClrEncrypted)this.MethodAttribute;
            }
        }

        public byte[] Decrypt()
        {
            byte[] encrypted_data = GetEncryptedSource();
            if(encrypted_data.Length == 0)
            {
                Win32.Print("ERROR: Failed to detect encrypted data for method!");
                return new byte[0];
            }

            Win32.Print("Encrypted: " + BitConverter.ToString(encrypted_data));

            byte[] decrypted_data = new byte[0];
            if(this.Encryption.Type == EncryptionType.aes)
            {
                decrypted_data = Decryption.DecryptAES(encrypted_data, GetDecryptionKey());
            }
            else if(this.Encryption.Type == EncryptionType.xor)
            {
                decrypted_data = Decryption.DecrypteXOR(encrypted_data, 0x16);
            }
            else if (this.Encryption.Type == EncryptionType.rsa)
            {
                decrypted_data = Decryption.DecryptRSA(encrypted_data, new byte[0]);
            }

            return decrypted_data;
        }

        protected string GetDecryptionKey()
        {
            if (DecryptionKey == "")
            {
                try
                {
                    if (System.IO.File.Exists("DECRYPTION.key"))
                    {
                        Win32.Print("Decryption Key On Disk! No User Prompt Required");
                        DecryptionKey = System.IO.File.ReadAllText("DECRYPTION.key");
                        return DecryptionKey;
                    }
                }
                catch { }
                DecryptionKey = Microsoft.VisualBasic.Interaction.InputBox("Please enter your decryption key.", "Decryption");

            }

            return DecryptionKey;
        }

        protected byte[] GetEncryptedSource()
        {
            if(this.Encryption.Streamed)
            {
                byte[] data = new byte[0];
                try
                {
                    if (DOWNLOAD_URL == "")
                        DOWNLOAD_URL = "http://dev.lystic.net/netprotect/test.php";

                    using (WebClient wc = new WebClient())
                    {
                        data = wc.DownloadData(DOWNLOAD_URL + "?m=src_" + this.Method.Name);
                    }
                }
                catch { }
                return data;
            }
            else
            {
#warning TRY THIS 
                Win32.Print($"Attempting to extract embedded resource for method {Method.Name}");
                try
                {
                    using (Stream res_stream = Method.Module.Assembly.GetManifestResourceStream(this.Method.Name))
                    {

                        byte[] encrypted_data = new byte[res_stream.Length];
                        res_stream.Read(encrypted_data, 0, encrypted_data.Length);
                        return encrypted_data;
                    }
                } catch(Exception ex)
                {
                    Win32.Print("ERROR: " + ex.Message);
                }
                //Temp: we need to embed this somehow
                //return System.IO.File.ReadAllBytes("src_" + this.Method.Name);
                return new byte[] { };
            }
        }
    }
}

using NetProtect.AntiTamper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetProtect
{
    public class MethodHash : Attribute
    {
        public string Hash { get; }
        public MethodHash(string md5_hash)
        {
            this.Hash = md5_hash;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetProtect.AntiTamper
{
    class SafeCrash
    {
        [MethodHash("uncomputed")]
        /// <summary>
        /// If something weird is happening, and we need to crash the application, this method will help us do so by crashing us on another thread.
        /// </summary>
        public static unsafe void ForceCrash()
        {
            Thread crash_thread = new Thread(new ThreadStart(() => {
                byte* value = (byte*)0x0;
                *value = 0;//null ptr exception
            }));
            crash_thread.Start();
            while(crash_thread.IsAlive)
            {
                Thread.Sleep(10);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace NetProtect.Extensibles
{
    internal static class Extensibles
    {
        internal static IntPtr GetHMODULE(this Module module)
        {
            ModuleHandle module_handle = module.ModuleHandle;
            var m_ptr = module_handle.GetType().GetField("m_ptr", BindingFlags.NonPublic | BindingFlags.Instance);
            var m_ptrValue = m_ptr.GetValue(module_handle);
            var m_ptrData = m_ptrValue.GetType().GetField("m_pData", BindingFlags.NonPublic | BindingFlags.Instance);
            IntPtr m_ptrDataValue = (IntPtr)m_ptrData.GetValue(m_ptrValue);
            return m_ptrDataValue;
        }
    }
}

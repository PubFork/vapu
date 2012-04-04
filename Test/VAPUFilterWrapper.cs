using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Diagnostics;

namespace VAPUFilterWrapper
{

    [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
    public struct GUID
    {

        /// unsigned int
        public uint Data1;

        /// unsigned short
        public ushort Data2;

        /// unsigned short
        public ushort Data3;

        /// unsigned char[8]
        [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 8)]
        public string Data4;
    }

    public partial class NativeMethods
    {
        /// Return Type: DWORD->unsigned int
        ///providerKey: GUID*
        ///providerName: PCWSTR->WCHAR*
        ///subLayerKey: GUID*
        ///subLayerName: PCWSTR->WCHAR*
        ///engine: HANDLE*
        [System.Runtime.InteropServices.DllImportAttribute("VAPUFilter.dll", EntryPoint = "Install")]
        public static extern uint Install([System.Runtime.InteropServices.InAttribute()] ref GUID providerKey, [System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string providerName, [System.Runtime.InteropServices.InAttribute()] ref GUID subLayerKey, [System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string subLayerName, ref System.IntPtr engine);

        /// Return Type: DWORD->unsigned int
        ///providerKey: GUID*
        ///subLayerKey: GUID*
        [System.Runtime.InteropServices.DllImportAttribute("VAPUFilter.dll", EntryPoint = "Uninstall")]
        public static extern uint Uninstall([System.Runtime.InteropServices.InAttribute()] ref GUID providerKey, [System.Runtime.InteropServices.InAttribute()] ref GUID subLayerKey);

        /// Return Type: DWORD->unsigned int
        ///szIpAddrToBlock: LPCSTR->CHAR*
        ///engine: HANDLE->void*
        ///subLayerKey: GUID*
        ///u64VistaFilterId: UINT64*
        [System.Runtime.InteropServices.DllImportAttribute("VAPUFilter.dll", EntryPoint = "AddFilter")]
        public static extern uint AddFilter([System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPStr)] string szIpAddrToBlock, System.IntPtr engine, [System.Runtime.InteropServices.InAttribute()] ref GUID subLayerKey, [System.Runtime.InteropServices.OutAttribute()] out ulong u64VistaFilterId);

        /// Return Type: DWORD->unsigned int
        ///engine: HANDLE->void*
        ///u64VistaFilterId: UINT64->unsigned __int64
        [System.Runtime.InteropServices.DllImportAttribute("VAPUFilter.dll", EntryPoint = "RemoveFilter")]
        public static extern uint RemoveFilter(System.IntPtr engine, ulong u64VistaFilterId);
    }

    public class VAPUDomainAddress
    {
        private List<VAPUIPAddress> _VapuIpAddressList;
        private String _DomainName;
        public List<VAPUIPAddress> VapuIpAddressList
        {
            set { _VapuIpAddressList = value; }
            get { return _VapuIpAddressList; }
        }

        public String DomainName
        {
            set { _DomainName = value; }
            get { return _DomainName; }
        }
    }

    public class VAPUIPAddress
    {
        private ulong _FilterId;
        private IPAddress _IpAddress;

        public ulong FilterId
        {
            set { _FilterId = value; }
            get { return _FilterId; }
        }

        public IPAddress IpAddress
        {
            set { _IpAddress = value; }
            get { return _IpAddress; }
        }

        public String ToString()
        {
            return IpAddress.ToString();
        }
    }

    public class FilterUtil
    {
        public static VAPUDomainAddress GetHoshEntry(String hostName)
        {
            VAPUDomainAddress vAPUDomainAddress = null;
            try
            {
                IPHostEntry NameToIpAddress = Dns.GetHostEntry(hostName);
                List<VAPUIPAddress> lstIP = new List<VAPUIPAddress>();
                foreach (IPAddress address in NameToIpAddress.AddressList)
                {
                    VAPUIPAddress vapuIp = new VAPUIPAddress();
                    vapuIp.IpAddress = address;
                    vapuIp.FilterId = 0;
                    lstIP.Add(vapuIp);
                }

                vAPUDomainAddress = new VAPUDomainAddress();
                vAPUDomainAddress.DomainName = hostName;
                vAPUDomainAddress.VapuIpAddressList = lstIP;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }

            return vAPUDomainAddress;
        }
    }

    public class Vista3
    {
        static void Main(String[] args)
        {
            GUID providerKey = new GUID();
            providerKey.Data1 = 10;
            providerKey.Data2 = 11;
            providerKey.Data3 = 12;
            providerKey.Data4 = "123";

            GUID subLayerKey = new GUID();
            subLayerKey.Data1 = 13;
            subLayerKey.Data2 = 14;
            subLayerKey.Data3 = 15;
            subLayerKey.Data4 = "456";

            IntPtr engine = new IntPtr();
            String domainName = "";
            ulong result = 0;

            result = NativeMethods.Install(ref providerKey, "Vista3Provider", ref subLayerKey, "Vista3SubLayer", ref engine);
            Console.WriteLine("CAI DAT ENGINE>>>" + result);

            List<VAPUDomainAddress> lstBlocked = new List<VAPUDomainAddress>();

            do
            {
                Console.WriteLine("Nhap domain name (nhap exit de thoat):");
                domainName = Console.ReadLine();
                VAPUDomainAddress vapuDomain = FilterUtil.GetHoshEntry(domainName);
                if (vapuDomain == null)
                {
                    if (!domainName.Equals("exit"))
                    {
                        Console.WriteLine("Khong tim thay domain");
                    }
                }
                else
                {
                    lstBlocked.Add(vapuDomain);

                    foreach (VAPUIPAddress ip in vapuDomain.VapuIpAddressList)
                    {
                        ulong filterId = 0;
                        result = NativeMethods.AddFilter(ip.ToString(), engine, ref subLayerKey, out filterId);
                        ip.FilterId = filterId;
                        Console.WriteLine("ADD FILTER >>>" + ip.ToString() + ":" + result + ":" + ip.FilterId);
                    }
                }
            } while (!domainName.Equals("exit"));

            foreach (VAPUDomainAddress domain in lstBlocked)
            {
                foreach (VAPUIPAddress ip in domain.VapuIpAddressList)
                {
                    result = NativeMethods.RemoveFilter(engine, ip.FilterId);
                    Console.WriteLine("REMOVE FILTER >>>" + ip.ToString() + ":" + result + ":" + ip.FilterId);
                }
            }

            result = NativeMethods.Uninstall(ref providerKey, ref subLayerKey);
            Console.WriteLine("GO BO ENGINE>>>" + result);
            Console.ReadLine();
        }
    }
}
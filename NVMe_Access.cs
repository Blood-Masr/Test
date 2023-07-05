using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using DebugManager;
using System.Threading;
using System.Management;
using AppSharingTool;
using System.Collections;
using AppSharingTool.ExtensionMethod;
using System.IO;
using System.Text.RegularExpressions;
using System.Management.Instrumentation;

namespace ATACmdSet
{
    /// <summary>
    /// 此頁共用的 結構體 / ENUM / 方法。
    /// </summary>
    public class ExternBase
    {
        #region DllImport
        // CreateFile to get handle to drive
        [DllImport("kernel32.dll", SetLastError = true)]
        public extern static IntPtr CreateFile(string FileName,
            uint DesiredAccess,
            uint ShareMode,
            IntPtr lpSecurityAttributes,
            uint CreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
        [MarshalAs(UnmanagedType.LPWStr)]
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int CloseHandle(IntPtr hObject);

        // DeviceIoControl to check nominal media rotation rate
        [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl",
        SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControlw(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);


        [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            ref uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int FlushFileBuffers(SafeFileHandle hFile);
        #endregion

        #region DEFINE ACCESS TYPES
        //
        // Constants
        //
        public const uint CREATE_NEW = 1;
        public const uint CREATE_ALWAYS = 2;
        public const uint OPEN_EXISTING = 3;
        public const uint OPEN_ALWAYS = 4;
        public const uint TRUNCATE_EXISTING = 5;
        // begin_access
        ////////////////////////////////////////////////////////////////////////
        //                                                                    //
        //                             ACCESS TYPES                           //
        //                                                                    //
        ////////////////////////////////////////////////////////////////////////


        // begin_wdm
        //
        //  The following are masks for the predefined standard access types
        //

        public const uint DELETE = (0x00010000);
        public const uint READ_CONTROL = (0x00020000);
        public const uint WRITE_DAC = (0x00040000);
        public const uint WRITE_OWNER = (0x00080000);
        public const uint SYNCHRONIZE = (0x00100000);

        public const uint STANDARD_RIGHTS_REQUIRED = (0x000F0000);

        public const uint STANDARD_RIGHTS_READ = (READ_CONTROL);
        public const uint STANDARD_RIGHTS_WRITE = (READ_CONTROL);
        public const uint STANDARD_RIGHTS_EXECUTE = (READ_CONTROL);

        public const uint STANDARD_RIGHTS_ALL = (0x001F0000);

        public const uint SPECIFIC_RIGHTS_ALL = (0x0000FFFF);

        //
        // AccessSystemAcl access type
        //

        public const uint ACCESS_SYSTEM_SECURITY = (0x01000000);

        //
        // MaximumAllowed access type
        //

        public const uint MAXIMUM_ALLOWED = (0x02000000);

        //
        //  These are the generic rights.
        //

        public const uint GENERIC_READ = (0x80000000);
        public const uint GENERIC_WRITE = (0x40000000);
        public const uint GENERIC_EXECUTE = (0x20000000);
        public const uint GENERIC_ALL = (0x10000000);

        //
        // Define access rights to files and directories
        //

        //
        // The FILE_READ_DATA and FILE_WRITE_DATA constants are also defined in
        // devioctl.h as FILE_READ_ACCESS and FILE_WRITE_ACCESS. The values for these
        // constants *MUST* always be in sync.
        // The values are redefined in devioctl.h because they must be available to
        // both DOS and NT.
        //

        public const UInt16 FILE_READ_DATA = (0x0001);       // file & pipe
        public const UInt16 FILE_LIST_DIRECTORY = (0x0001);       // directory

        public const UInt16 FILE_WRITE_DATA = (0x0002);       // file & pipe
        public const UInt16 FILE_ADD_FILE = (0x0002);       // directory

        public const UInt16 FILE_APPEND_DATA = (0x0004);    // file
        public const UInt16 FILE_ADD_SUBDIRECTORY = (0x0004);    // directory
        public const UInt16 FILE_CREATE_PIPE_INSTANCE = (0x0004);    // named pipe


        public const UInt16 FILE_READ_EA = (0x0008);    // file & directory

        public const UInt16 FILE_WRITE_EA = (0x0010);    // file & directory

        public const UInt16 FILE_EXECUTE = (0x0020);    // file
        public const UInt16 FILE_TRAVERSE = (0x0020);    // directory

        public const UInt16 FILE_DELETE_CHILD = (0x0040);    // directory

        public const UInt16 FILE_READ_ATTRIBUTES = (0x0080);    // all

        public const UInt16 FILE_WRITE_ATTRIBUTES = (0x0100);    // all

        public const uint FILE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF);

        public const uint FILE_GENERIC_READ = (STANDARD_RIGHTS_READ | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE);


        public const uint FILE_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_APPEND_DATA | SYNCHRONIZE);


        public const uint FILE_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE | FILE_READ_ATTRIBUTES | FILE_EXECUTE | SYNCHRONIZE);

        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint FILE_SHARE_DELETE = 0x00000004;
        public const uint FILE_ATTRIBUTE_READONLY = 0x00000001;
        public const uint FILE_ATTRIBUTE_HIDDEN = 0x00000002;
        public const uint FILE_ATTRIBUTE_SYSTEM = 0x00000004;
        public const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        public const uint FILE_ATTRIBUTE_ARCHIVE = 0x00000020;
        public const uint FILE_ATTRIBUTE_DEVICE = 0x00000040;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        public const uint FILE_ATTRIBUTE_TEMPORARY = 0x00000100;
        public const uint FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200;
        public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        public const uint FILE_ATTRIBUTE_COMPRESSED = 0x00000800;
        public const uint FILE_ATTRIBUTE_OFFLINE = 0x00001000;
        public const uint FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = 0x00002000;
        public const uint FILE_ATTRIBUTE_ENCRYPTED = 0x00004000;
        public const uint FILE_ATTRIBUTE_INTEGRITY_STREAM = 0x00008000;
        public const uint FILE_ATTRIBUTE_VIRTUAL = 0x00010000;
        public const uint FILE_ATTRIBUTE_NO_SCRUB_DATA = 0x00020000;
        public const uint FILE_ATTRIBUTE_EA = 0x00040000;
        public const uint FILE_ATTRIBUTE_PINNED = 0x00080000;
        public const uint FILE_ATTRIBUTE_UNPINNED = 0x00100000;
        public const uint FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000;
        public const uint FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000;
        public const uint TREE_CONNECT_ATTRIBUTE_PRIVACY = 0x00004000;
        public const uint TREE_CONNECT_ATTRIBUTE_INTEGRITY = 0x00008000;
        public const uint TREE_CONNECT_ATTRIBUTE_GLOBAL = 0x00000004;
        public const uint TREE_CONNECT_ATTRIBUTE_PINNED = 0x00000002;
        public const uint FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL = 0x20000000;
        public const uint FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001;
        public const uint FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002;
        public const uint FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004;
        public const uint FILE_NOTIFY_CHANGE_SIZE = 0x00000008;
        public const uint FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010;
        public const uint FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020;
        public const uint FILE_NOTIFY_CHANGE_CREATION = 0x00000040;
        public const uint FILE_NOTIFY_CHANGE_SECURITY = 0x00000100;
        public const uint FILE_ACTION_ADDED = 0x00000001;
        public const uint FILE_ACTION_REMOVED = 0x00000002;
        public const uint FILE_ACTION_MODIFIED = 0x00000003;
        public const uint FILE_ACTION_RENAMED_OLD_NAME = 0x00000004;
        public const uint FILE_ACTION_RENAMED_NEW_NAME = 0x00000005;
        public const uint MAILSLOT_NO_MESSAGE = ((UInt32.MaxValue) - 1);
        public const uint MAILSLOT_WAIT_FOREVER = ((UInt32.MaxValue) - 1);
        public const uint FILE_CASE_SENSITIVE_SEARCH = 0x00000001;
        public const uint FILE_CASE_PRESERVED_NAMES = 0x00000002;
        public const uint FILE_UNICODE_ON_DISK = 0x00000004;
        public const uint FILE_PERSISTENT_ACLS = 0x00000008;
        public const uint FILE_FILE_COMPRESSION = 0x00000010;
        public const uint FILE_VOLUME_QUOTAS = 0x00000020;
        public const uint FILE_SUPPORTS_SPARSE_FILES = 0x00000040;
        public const uint FILE_SUPPORTS_REPARSE_POINTS = 0x00000080;
        public const uint FILE_SUPPORTS_REMOTE_STORAGE = 0x00000100;
        public const uint FILE_RETURNS_CLEANUP_RESULT_INFO = 0x00000200;
        public const uint FILE_SUPPORTS_POSIX_UNLINK_RENAME = 0x00000400;




        public const uint FILE_VOLUME_IS_COMPRESSED = 0x00008000;
        public const uint FILE_SUPPORTS_OBJECT_IDS = 0x00010000;
        public const uint FILE_SUPPORTS_ENCRYPTION = 0x00020000;
        public const uint FILE_NAMED_STREAMS = 0x00040000;
        public const uint FILE_READ_ONLY_VOLUME = 0x00080000;
        public const uint FILE_SEQUENTIAL_WRITE_ONCE = 0x00100000;
        public const uint FILE_SUPPORTS_TRANSACTIONS = 0x00200000;
        public const uint FILE_SUPPORTS_HARD_LINKS = 0x00400000;
        public const uint FILE_SUPPORTS_EXTENDED_ATTRIBUTES = 0x00800000;
        public const uint FILE_SUPPORTS_OPEN_BY_FILE_ID = 0x01000000;
        public const uint FILE_SUPPORTS_USN_JOURNAL = 0x02000000;
        public const uint FILE_SUPPORTS_INTEGRITY_STREAMS = 0x04000000;
        public const uint FILE_SUPPORTS_BLOCK_REFCOUNTING = 0x08000000;
        public const uint FILE_SUPPORTS_SPARSE_VDL = 0x10000000;
        public const uint FILE_DAX_VOLUME = 0x20000000;
        public const uint FILE_SUPPORTS_GHOSTING = 0x40000000;

        public const UInt64 FILE_INVALID_FILE_ID = ((UInt64.MaxValue) - 1);

        // begin_ntddk begin_wdm begin_nthal begin_ntifs
        //
        // Define the various device type values.  Note that values used by Microsoft
        // Corporation are in the range 0-32767, and 32768-65535 are reserved for use
        // by customers.
        //

        public const UInt32 DEVICE_TYPE = UInt32.MaxValue;

        public const UInt64 FILE_DEVICE_BEEP = 0x00000001;
        public const UInt64 FILE_DEVICE_CD_ROM = 0x00000002;
        public const UInt64 FILE_DEVICE_CD_ROM_FILE_SYSTEM = 0x00000003;
        public const UInt64 FILE_DEVICE_CONTROLLER = 0x00000004;
        public const UInt64 FILE_DEVICE_DATALINK = 0x00000005;
        public const UInt64 FILE_DEVICE_DFS = 0x00000006;
        public const UInt64 FILE_DEVICE_DISK = 0x00000007;
        public const UInt64 FILE_DEVICE_DISK_FILE_SYSTEM = 0x00000008;
        public const UInt64 FILE_DEVICE_FILE_SYSTEM = 0x00000009;
        public const UInt64 FILE_DEVICE_INPORT_PORT = 0x0000000a;
        public const UInt64 FILE_DEVICE_KEYBOARD = 0x0000000b;
        public const UInt64 FILE_DEVICE_MAILSLOT = 0x0000000c;
        public const UInt64 FILE_DEVICE_MIDI_IN = 0x0000000d;
        public const UInt64 FILE_DEVICE_MIDI_OUT = 0x0000000e;
        public const UInt64 FILE_DEVICE_MOUSE = 0x0000000f;
        public const UInt64 FILE_DEVICE_MULTI_UNC_PROVIDER = 0x00000010;
        public const UInt64 FILE_DEVICE_NAMED_PIPE = 0x00000011;
        public const UInt64 FILE_DEVICE_NETWORK = 0x00000012;
        public const UInt64 FILE_DEVICE_NETWORK_BROWSER = 0x00000013;
        public const UInt64 FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x00000014;
        public const UInt64 FILE_DEVICE_NULL = 0x00000015;
        public const UInt64 FILE_DEVICE_PARALLEL_PORT = 0x00000016;
        public const UInt64 FILE_DEVICE_PHYSICAL_NETCARD = 0x00000017;
        public const UInt64 FILE_DEVICE_PRINTER = 0x00000018;
        public const UInt64 FILE_DEVICE_SCANNER = 0x00000019;
        public const UInt64 FILE_DEVICE_SERIAL_MOUSE_PORT = 0x0000001a;
        public const UInt64 FILE_DEVICE_SERIAL_PORT = 0x0000001b;
        public const UInt64 FILE_DEVICE_SCREEN = 0x0000001c;
        public const UInt64 FILE_DEVICE_SOUND = 0x0000001d;
        public const UInt64 FILE_DEVICE_STREAMS = 0x0000001e;
        public const UInt64 FILE_DEVICE_TAPE = 0x0000001f;
        public const UInt64 FILE_DEVICE_TAPE_FILE_SYSTEM = 0x00000020;
        public const UInt64 FILE_DEVICE_TRANSPORT = 0x00000021;
        public const UInt64 FILE_DEVICE_UNKNOWN = 0x00000022;
        public const UInt64 FILE_DEVICE_VIDEO = 0x00000023;
        public const UInt64 FILE_DEVICE_VIRTUAL_DISK = 0x00000024;
        public const UInt64 FILE_DEVICE_WAVE_IN = 0x00000025;
        public const UInt64 FILE_DEVICE_WAVE_OUT = 0x00000026;
        public const UInt64 FILE_DEVICE_8042_PORT = 0x00000027;
        public const UInt64 FILE_DEVICE_NETWORK_REDIRECTOR = 0x00000028;
        public const UInt64 FILE_DEVICE_BATTERY = 0x00000029;
        public const UInt64 FILE_DEVICE_BUS_EXTENDER = 0x0000002a;
        public const UInt64 FILE_DEVICE_MODEM = 0x0000002b;
        public const UInt64 FILE_DEVICE_VDM = 0x0000002c;
        public const UInt64 FILE_DEVICE_MASS_STORAGE = 0x0000002d;
        public const UInt64 FILE_DEVICE_SMB = 0x0000002e;
        public const UInt64 FILE_DEVICE_KS = 0x0000002f;
        public const UInt64 FILE_DEVICE_CHANGER = 0x00000030;
        public const UInt64 FILE_DEVICE_SMARTCARD = 0x00000031;
        public const UInt64 FILE_DEVICE_ACPI = 0x00000032;
        public const UInt64 FILE_DEVICE_DVD = 0x00000033;
        public const UInt64 FILE_DEVICE_FULLSCREEN_VIDEO = 0x00000034;
        public const UInt64 FILE_DEVICE_DFS_FILE_SYSTEM = 0x00000035;
        public const UInt64 FILE_DEVICE_DFS_VOLUME = 0x00000036;
        public const UInt64 FILE_DEVICE_SERENUM = 0x00000037;
        public const UInt64 FILE_DEVICE_TERMSRV = 0x00000038;
        public const UInt64 FILE_DEVICE_KSEC = 0x00000039;
        public const UInt64 FILE_DEVICE_FIPS = 0x0000003A;
        public const UInt64 FILE_DEVICE_INFINIBAND = 0x0000003B;
        public const UInt64 FILE_DEVICE_VMBUS = 0x0000003E;
        public const UInt64 FILE_DEVICE_CRYPT_PROVIDER = 0x0000003F;
        public const UInt64 FILE_DEVICE_WPD = 0x00000040;
        public const UInt64 FILE_DEVICE_BLUETOOTH = 0x00000041;
        public const UInt64 FILE_DEVICE_MT_COMPOSITE = 0x00000042;
        public const UInt64 FILE_DEVICE_MT_TRANSPORT = 0x00000043;
        public const UInt64 FILE_DEVICE_BIOMETRIC = 0x00000044;
        public const UInt64 FILE_DEVICE_PMI = 0x00000045;
        public const UInt64 FILE_DEVICE_EHSTOR = 0x00000046;
        public const UInt64 FILE_DEVICE_DEVAPI = 0x00000047;
        public const UInt64 FILE_DEVICE_GPIO = 0x00000048;
        public const UInt64 FILE_DEVICE_USBEX = 0x00000049;
        public const UInt64 FILE_DEVICE_CONSOLE = 0x00000050;
        public const UInt64 FILE_DEVICE_NFP = 0x00000051;
        public const UInt64 FILE_DEVICE_SYSENV = 0x00000052;
        public const UInt64 FILE_DEVICE_VIRTUAL_BLOCK = 0x00000053;
        public const UInt64 FILE_DEVICE_POINT_OF_SERVICE = 0x00000054;
        public const UInt64 FILE_DEVICE_STORAGE_REPLICATION = 0x00000055;
        public const UInt64 FILE_DEVICE_TRUST_ENV = 0x00000056;
        public const UInt64 FILE_DEVICE_UCM = 0x00000057;
        public const UInt64 FILE_DEVICE_UCMTCPCI = 0x00000058;
        public const UInt64 FILE_DEVICE_PERSISTENT_MEMORY = 0x00000059;
        public const UInt64 FILE_DEVICE_NVDIMM = 0x0000005a;
        public const UInt64 FILE_DEVICE_HOLOGRAPHIC = 0x0000005b;
        public const UInt64 FILE_DEVICE_SDFXHCI = 0x0000005c;
        public const UInt64 FILE_DEVICE_UCMUCSI = 0x0000005d;

        //
        // Macro definition for defining IOCTL and FSCTL function control codes.  Note
        // that function codes 0-2047 are reserved for Microsoft Corporation, and
        // 2048-4095 are reserved for customers.
        //
        public static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
        {
            return ((DeviceType << 16) | (Access << 14) |
            (Function << 2) | Method);
        }

        //
        // Define the method codes for how buffers are passed for I/O and FS controls
        //

        public const uint METHOD_BUFFERED = 0;
        public const uint METHOD_IN_DIRECT = 1;
        public const uint METHOD_OUT_DIRECT = 2;
        public const uint METHOD_NEITHER = 3;

        //
        // Define the access check value for any access
        //
        //
        // The FILE_READ_ACCESS and FILE_WRITE_ACCESS constants are also defined in
        // ntioapi.h as FILE_READ_DATA and FILE_WRITE_DATA. The values for these
        // constants *MUST* always be in sync.
        //
        //
        // FILE_SPECIAL_ACCESS is checked by the NT I/O system the same as FILE_ANY_ACCESS.
        // The file systems, however, may add additional access checks for I/O and FS controls
        // that use this value.
        //


        public const uint FILE_ANY_ACCESS = 0;
        public const uint FILE_SPECIAL_ACCESS = (FILE_ANY_ACCESS);
        public const uint FILE_READ_ACCESS = (0x0001);    // file & pipe
        public const uint FILE_WRITE_ACCESS = (0x0002);    // file & pipe

        //From DDK

        public const UInt64 FILE_DEVICE_SCSI = 0x0000001b;
        public const UInt64 IOCTL_SCSI_MINIPORT_IDENTIFY = ((FILE_DEVICE_SCSI << 16) + 0x0501);
        public const UInt64 IOCTL_SCSI_MINIPORT_READ_SMART_ATTRIBS = ((FILE_DEVICE_SCSI << 16) + 0x0502);
        public const UInt64 IOCTL_SCSI_MINIPORT_READ_SMART_THRESHOLDS = ((FILE_DEVICE_SCSI << 16) + 0x0503);
        public const UInt64 IOCTL_SCSI_MINIPORT_ENABLE_SMART = ((FILE_DEVICE_SCSI << 16) + 0x0504);
        public const UInt64 IOCTL_SCSI_MINIPORT_DISABLE_SMART = ((FILE_DEVICE_SCSI << 16) + 0x0505);

        public const UInt64 IOCTL_SCSI_BASE = FILE_DEVICE_CONTROLLER;
        public static uint IOCTL_SCSI_PASS_THROUGH = CTL_CODE((UInt32)IOCTL_SCSI_BASE, 0x0401, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

        //
        // Define values for pass-through DataIn field.
        //
        public const UInt32 SCSI_IOCTL_DATA_OUT = 0;
        public const UInt32 SCSI_IOCTL_DATA_IN = 1;
        public const UInt32 SCSI_IOCTL_DATA_UNSPECIFIED = 2;

        ///////////////////////////////////////////////////
        // from http://naraeon.net/en/archives/1126
        ///////////////////////////////////////////////////

        public const uint NVME_STORPORT_DRIVER = 0xE000;
        public static Int32 NVME_PASS_THROUGH_SRB_IO_CODE = (Int32)CTL_CODE(NVME_STORPORT_DRIVER, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public const string NVME_SIG_STR = "NvmeMini";
        public const Int32 NVME_SIG_STR_LEN = 8;
        public const Int32 NVME_FROM_DEV_TO_HOST = 2;
        public const Int32 NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE = 6;
        public const Int32 NVME_IOCTL_CMD_DW_SIZE = 16;
        public const Int32 NVME_IOCTL_COMPLETE_DW_SIZE = 4;
        public const Int32 NVME_PT_TIMEOUT = 40;

        public static uint IOCTL_SCSI_GET_ADDRESS = CTL_CODE((UInt32)IOCTL_SCSI_BASE, 0x0406, METHOD_BUFFERED, FILE_ANY_ACCESS);

        public const Int32 READ_ATTRIBUTE_BUFFER_SIZE = 512;
        public const Int32 IDENTIFY_BUFFER_SIZE = 512;
        public const Int32 READ_THRESHOLD_BUFFER_SIZE = 512;
        public const Int32 SMART_LOG_SECTOR_SIZE = 512;

        //
        // Feature register defines for SMART "sub commands"
        //

        public const Int32 READ_ATTRIBUTES = 0xD0;
        public const Int32 READ_THRESHOLDS = 0xD1;
        public const Int32 ENABLE_DISABLE_AUTOSAVE = 0xD2;
        public const Int32 SAVE_ATTRIBUTE_VALUES = 0xD3;
        public const Int32 EXECUTE_OFFLINE_DIAGS = 0xD4;
        public const Int32 SMART_READ_LOG = 0xD5;
        public const Int32 SMART_WRITE_LOG = 0xd6;
        public const Int32 ENABLE_SMART = 0xD8;
        public const Int32 DISABLE_SMART = 0xD9;
        public const Int32 RETURN_SMART_STATUS = 0xDA;
        public const Int32 ENABLE_DISABLE_AUTO_OFFLINE = 0xDB;

        //
        // Valid values for the bCommandReg member of IDEREGS.
        //

        public const Int32 ATAPI_ID_CMD = 0xA1;            // Returns ID sector for ATAPI.
        public const Int32 ID_CMD = 0xEC;            // Returns ID sector for ATA.
        public const Int32 SMART_CMD = 0xB0;            // Performs SMART cmd.

        //
        // Cylinder register defines for SMART command
        //

        public const Int32 SMART_CYL_LOW = 0x4F;
        public const Int32 SMART_CYL_HI = 0xC2;

        //
        // IoControlCode values for storage devices
        //

        public const Int32 IOCTL_STORAGE_BASE = (Int32)FILE_DEVICE_MASS_STORAGE;

        //
        // IOCTLs 0x0470 to 0x047f reserved for device and stack telemetry interfaces
        //

        public static Int32 IOCTL_STORAGE_GET_DEVICE_TELEMETRY = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x0470, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
        public static Int32 IOCTL_STORAGE_DEVICE_TELEMETRY_NOTIFY = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x0471, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
        public static Int32 IOCTL_STORAGE_DEVICE_TELEMETRY_QUERY_CAPS = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x0472, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);
        public static Int32 IOCTL_STORAGE_GET_DEVICE_TELEMETRY_RAW = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x0473, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);


        public static Int32 IOCTL_STORAGE_SET_TEMPERATURE_THRESHOLD = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x0480, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

        public static Int32 IOCTL_STORAGE_PROTOCOL_COMMAND = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x04F0, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS);

        public static Int32 IOCTL_STORAGE_QUERY_PROPERTY = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS);
        public static Int32 IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x0501, METHOD_BUFFERED, FILE_WRITE_ACCESS);
        public static Int32 IOCTL_STORAGE_GET_LB_PROVISIONING_MAP_RESOURCES = (Int32)CTL_CODE(IOCTL_STORAGE_BASE, 0x0502, METHOD_BUFFERED, FILE_READ_ACCESS);

        public const Int32 ANYSIZE_ARRAY = 0x1;

        #region STORAGE_PROTOCOL 相關定義

        /// <summary>
        /// Bit-mask values for STORAGE_PROTOCOL_COMMAND - "Flags" field.
        /// Flag indicates the request targeting to adapter instead of device.
        /// </summary>
        public const UInt32 STORAGE_PROTOCOL_COMMAND_FLAG_ADAPTER_REQUEST = 0x80000000;

        /// <summary>
        /// Status values for STORAGE_PROTOCOL_COMMAND - "ReturnStatus" field.
        /// </summary>
        public const UInt32 STORAGE_PROTOCOL_STATUS_PENDING = 0x0;
        public const UInt32 STORAGE_PROTOCOL_STATUS_SUCCESS = 0x1;
        public const UInt32 STORAGE_PROTOCOL_STATUS_ERROR = 0x2;
        public const UInt32 STORAGE_PROTOCOL_STATUS_INVALID_REQUEST = 0x3;
        public const UInt32 STORAGE_PROTOCOL_STATUS_NO_DEVICE = 0x4;
        public const UInt32 STORAGE_PROTOCOL_STATUS_BUSY = 0x5;
        public const UInt32 STORAGE_PROTOCOL_STATUS_DATA_OVERRUN = 0x6;
        public const UInt32 STORAGE_PROTOCOL_STATUS_INSUFFICIENT_RESOURCES = 0x7;
        public const UInt32 STORAGE_PROTOCOL_STATUS_THROTTLED_REQUEST = 0x8;
        public const UInt32 STORAGE_PROTOCOL_STATUS_NOT_SUPPORTED = 0xFF;

        /// <summary>
        /// Command Length for Storage Protocols.
        /// NVMe commands are always 64 bytes
        /// </summary>
        public const UInt32 STORAGE_PROTOCOL_COMMAND_LENGTH_NVME = 0x40;

        /// <summary>
        /// Command Specific Information for Storage Protocols - "CommandSpecific" field.
        /// </summary>
        public const UInt32 STORAGE_PROTOCOL_SPECIFIC_NVME_ADMIN_COMMAND = 0x01;
        public const UInt32 STORAGE_PROTOCOL_SPECIFIC_NVME_NVM_COMMAND = 0x02;
        #endregion

        /// <summary>
        /// Parameter for IOCTL_STORAGE_PROTOCOL_COMMAND
        /// Buffer layout: <STORAGE_PROTOCOL_COMMAND> <Command> [Error Info Buffer] [Data-to-Device Buffer] [Data-from-Device Buffer]
        /// </summary>
        public const Int32 STORAGE_PROTOCOL_STRUCTURE_VERSION = 0x1;

        /// <summary>
        /// If the namespace is not used for the command, then 'NSID' field shall be cleared to 0h.
        /// If a command shall be applied to all namespaces on the device, then 'NSID' field shall be set to FFFFFFFFh.
        /// </summary>
        public const UInt32 NVME_NAMESPACE_ALL = 0xFFFFFFFF;

        #endregion

        #region 結構體

        #region SATA 結構體
        [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 12)]
        public struct IND_ATTR_DATA
        {
            public byte bAttrID;
            public ushort wStatusFlag;
            public byte bAttrValue;
            public byte bWorst;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] abRaw;
            public byte bReserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 512)]
        public struct IDSECTOR
        {
            public ushort wGenConfig;                 // WORD 0: Basic Info. Word
            public ushort wNumCyls;                   // WORD 1: Cylinder Num.
            public ushort wReserved2;                 // WORD 2: Reserved
            public ushort wNumHeads;                  // WORD 3: Heads Num.
            public ushort wReserved4;                 // WORD 4: Reserved
            public ushort wReserved5;                 // WORD 5: Reserved
            public ushort wNumSectorsPerTrack;        // WORD 6: Sectors Num/Track
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public ushort[] wVendorUnique;           // WORD 7-9: Vender specifics
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public char[] sSerialNumber;          // WORD 10-19:Serial Num.
            public ushort wBufferType;                // WORD 20: Cache Type
            public ushort wBufferSize;                // WORD 21: Cache Size
            public ushort wECCSize;                   // WORD 22: ECC Size
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public Char[] sFirmwareRev;            // WORD 23-26: Firmware Ver.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
            public Char[] sModelNumber;           // WORD 27-46: Model Num.
            public ushort wMoreVendorUnique;          // WORD 47: Vender specifics
            public ushort wReserved48;                // WORD 48: Reserved
            public ushort wCapabilities;
            //wCapabilities wcapabilities;
            //[StructLayout(LayoutKind.Explicit)]
            ////[StructLayout(LayoutKind.Explicit, Size = 1, CharSet = CharSet.Ansi)]
            //struct wCapabilities
            //{
            //    [FieldOffset(0)]
            //    PackedByte data1;
            //    public byte reserved1
            //    {
            //        get { return (byte)data1.Get(0, 8); }
            //        set { data1.Set(0, 8, (byte)value); }
            //    }
            //public byte DMA
            //{
            //    get { return data1.Get(8, 1) != 0; }
            //    set { data1.Set(8, 1, value?(byte)1:(byte)0); }
            //}
            //[FieldOffset(0)]
            //byte reserved1;
            //[FieldOffset(1)]
            //byte DMA;                     // 1=Support DMA
            //[FieldOffset(2)]
            //byte LBA;                 // 1=Support LBA
            //[FieldOffset(3)]
            //byte DisIORDY;                // 1=Use IORDY
            //[FieldOffset(4)]
            //byte IORDY;               // 1=Support IORDY
            //[FieldOffset(5)]
            //byte SoftReset;           // 1=ATA soft reset
            //[FieldOffset(6)]
            //byte Overlap;             // 1=Support Overlap
            //[FieldOffset(7)]
            //byte Queue;               // 1=Support Queue
            //[FieldOffset(8)]
            //byte InlDMA;              // 1=Support interlease access DMA
            //   }                               // WORD 49: Capabilities

            public ushort wReserved50;                 // WORD 50: Reserved
            public ushort wPIOTiming;                 // WORD 51: PIO Timing
            public ushort wDMATiming;                 // WORD 52: DMA Timing
            public ushort wFieldValidity;
            //public struct wFieldValidity
            //{
            //    [BitfieldLength(1)]
            //    ushort CHSNumber;           // 1=WORD 54-58
            //    [BitfieldLength(1)]
            //    ushort CycleNumber;         // 1=WORD 64-70
            //    [BitfieldLength(1)]
            //    ushort UnltraDMA;           // 1=WORD 88
            //    [BitfieldLength(13)]
            //    ushort reserved;
            //}                               // WORD 53: Field Validity mark
            public ushort wNumCurCyls;                // WORD 54: CHS addressable Cylinder Num.
            public ushort wNumCurHeads;               // WORD 55: CHS addressabl Head Num.
            public ushort wNumCurSectorsPerTrack;     // WORD 56: CHS addressabl Sectors/Track
            public ushort wCurSectorsLow;             // WORD 57: CHS addressabl Sector Num. Low Word
            public ushort wCurSectorsHigh;            // WORD 58: CHS addressabl Sector Num. High Word
            public ushort wMultSectorStuff;
            //public struct wMultSectorStuff
            //{
            //    [BitfieldLength(8)]
            //    ushort CurNumber;           // Curret Re-Writable Sector Num
            //    [BitfieldLength(1)]
            //    ushort Multi;               // 1=Multi-Sector R/W seted
            //    [BitfieldLength(7)]
            //    ushort reserved1;
            //}                               // WORD 59: Multi-Sector R/W Setting
            public UInt32 dwTotalSectors;              // WORD 60-61: LBA addressable Sector Num.
            public ushort wSingleWordDMA;             // WORD 62: Single Word DMA support capability
            public ushort wMultiWordDMA;
            //public struct wMultiWordDMA
            //{
            //    [BitfieldLength(1)]
            //    ushort Mode0;               // 1=Supported Mode0 (4.17Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode1;               // 1=Supported Mode1 (13.3Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode2;               // 1=Supported Mode2 (16.7Mb/s)
            //    [BitfieldLength(5)]
            //    ushort Reserved1;
            //    [BitfieldLength(1)]
            //    ushort Mode0Sel;                // 1=Selected Mode0
            //    [BitfieldLength(1)]
            //    ushort Mode1Sel;                // 1=Selected Mode1
            //    [BitfieldLength(1)]
            //    ushort Mode2Sel;                // 1=Selected Mode2
            //    [BitfieldLength(5)]
            //    ushort Reserved2;
            //}                                   // WORD 63: Multi-Word DMA Supported capability
            public ushort wPIOCapacity;
            //public struct wPIOCapacity
            //{
            //    [BitfieldLength(8)]
            //    ushort AdvPOIModes;             // Support Advance POI Mode Num.
            //    [BitfieldLength(8)]
            //    ushort reserved;
            //}                                   // WORD 64: Advance PIO supported
            public ushort wMinMultiWordDMACycle;      // WORD 65: Multi-Word DMA transfer cycle min.
            public ushort wRecMultiWordDMACycle;      // WORD 66: Multi-Word DMA transfer cycle recomment
            public ushort wMinPIONoFlowCycle;         // WORD 67: No flow control PIO transfer cycle min.
            public ushort wMinPOIFlowCycle;           // WORD 68: Flow control PIO transfer cycle min.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public ushort[] wReserved69;            // WORD 69-74: Reserved
            public ushort wQueueDepth;
            public ushort wSATACapabilities;        //  WORD 76: 可以檢查設備支援最高的 SATA 模式，參考CDI。
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public ushort[] ReservedWords77;        //  WORD 77~79 : 77可以檢查設備當前的 SATA模式，參考CDI。
            public ushort wMajorVersion;
            //public struct wMajorVersion
            //{
            //    [BitfieldLength(1)]
            //    ushort Reserved1;
            //    [BitfieldLength(1)]
            //    ushort ATA1;                    // 1=Support ATA-1
            //    [BitfieldLength(1)]
            //    ushort ATA2;                    // 1=Support ATA-2
            //    [BitfieldLength(1)]
            //    ushort ATA3;                    // 1=Support ATA-3
            //    [BitfieldLength(1)]
            //    ushort ATA4;                    // 1=Support ATA/ATAPI-4
            //    [BitfieldLength(1)]
            //    ushort ATA5;                    // 1=Support ATA/ATAPI-5
            //    [BitfieldLength(1)]
            //    ushort ATA6;                    // 1=Support ATA/ATAPI-6
            //    [BitfieldLength(1)]
            //    ushort ATA7;                    // 1=Support ATA/ATAPI-7
            //    [BitfieldLength(1)]
            //    ushort ATA8;                    // 1=Support ATA/ATAPI-8
            //    [BitfieldLength(1)]
            //    ushort ATA9;                    // 1=Support ATA/ATAPI-9
            //    [BitfieldLength(1)]
            //    ushort ATA10;               // 1=Support ATA/ATAPI-10
            //    [BitfieldLength(1)]
            //    ushort ATA11;               // 1=Support ATA/ATAPI-11
            //    [BitfieldLength(1)]
            //    ushort ATA12;               // 1=Support ATA/ATAPI-12
            //    [BitfieldLength(1)]
            //    ushort ATA13;               // 1=Support ATA/ATAPI-13
            //    [BitfieldLength(1)]
            //    ushort ATA14;               // 1=Support ATA/ATAPI-14
            //    [BitfieldLength(1)]
            //    ushort Reserved2;
            //}                     // WORD 80: Major Version
            public ushort wMinorVersion;              // WORD 81: Minor Version
            public ushort wCommandandFeatureSetSupported;              // WORD 82: Commands and Feature Sets Supported
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
            public ushort[] wReserved83;             // WORD 83-87: Reserved
            public ushort wUltraDMA;
            //public struct wUltraDMA
            //{
            //    [BitfieldLength(1)]
            //    ushort Mode0;               // 1=Supported Mode0 (16.7Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode1;               // 1=Supported Mode1 (25Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode2;               // 1=Supported Mode2 (33Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode3;               // 1=Supported Mode3 (44Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode4;               // 1=Supported Mode4 (66Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode5;               // 1=Supported Mode5 (100Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode6;               // 1=Supported Mode6 (133Mb/s)
            //    [BitfieldLength(1)]
            //    ushort Mode7;               // 1=Supported Mode7 (166Mb/s) ???
            //    [BitfieldLength(1)]
            //    ushort Mode0Sel;                // 1=Selected Mode0
            //    [BitfieldLength(1)]
            //    ushort Mode1Sel;                // 1=Selected Mode1
            //    [BitfieldLength(1)]
            //    ushort Mode2Sel;                // 1=Selected Mode2
            //    [BitfieldLength(1)]
            //    ushort Mode3Sel;                // 1=Selected Mode3
            //    [BitfieldLength(1)]
            //    ushort Mode4Sel;                // 1=Selected Mode4
            //    [BitfieldLength(1)]
            //    ushort Mode5Sel;                // 1=Selected Mode5
            //    [BitfieldLength(1)]
            //    ushort Mode6Sel;                // 1=Selected Mode6
            //    [BitfieldLength(1)]
            //    ushort Mode7Sel;                // 1=Selected Mode7
            //}                         // WORD 88:  Ultra DMA Supported
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] wReserved89;
            public ushort wHardwareResetResult;
            public byte bCurrentAcousticValue;
            public byte bRecommendedAcousticValue;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
            public ushort[] wReserved95;
            public Int64 dwMax48BitLBA;
            public ushort wStreamingTransferTime;
            public ushort wReserved105;
            public ushort wPhysicalLogicalSectorSize;
            /*
            UInt16 LogicalSectorsPerPhysicalSector  :4;
            UInt16 Reserved0  :8;
            UInt16 LogicalSectorLongerThan256Words  :1;
            UInt16 MultipleLogicalSectorsPerPhysicalSector  :1;
            UInt16 Reserved1  :2;
            */
            //* Word 107 *//
            public ushort wInterSeekDelay;
            //* Word 108 *//
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] wWorldWideName;
            //* Word 112 *//
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] wReservedForWorldWideName112;
            //* Word 116 *//
            public ushort wReservedForTlcTechnicalReport;
            //* Word 117 *//
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ushort[] wWordsPerLogicalSector;
            //* Word 119 *//
            public ushort wCommandSetSupportExt;
            /*
            UInt16 ReservedForDrqTechnicalReport  :1;
            UInt16 WriteReadVerifySupported  :1;
            UInt16 Reserved01  :11;
            UInt16 Reserved1  :2;
            */

            //* Word 120 *//
            public ushort wCommandSetActiveExt;
            /*
            UInt16 ReservedForDrqTechnicalReport  :1;
            UInt16 WriteReadVerifyEnabled  :1;
            UInt16 Reserved01  :11;
            UInt16 Reserved1  :2;
            */
            //* Word 121 *//
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public ushort[] wReservedForExpandedSupportandActive;
            //* Word 127 *//
            public ushort wMsnSupport;
            //* Word 128 *//
            public ushort wSecurityStatus;
            /*
            UInt16 SecuritySupported  :1;
            UInt16 SecurityEnabled  :1;
            UInt16 SecurityLocked  :1;
            UInt16 SecurityFrozen  :1;
            UInt16 SecurityCountExpired  :1;
            UInt16 EnhancedSecurityEraseSupported  :1;
            UInt16 Reserved0  :2;
            UInt16 SecurityLevel  :1;
            UInt16 Reserved1  :7;
            */

            //* Word 129 *//
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 31)]
            public ushort[] wReserved129;
            public ushort wCfaPowerModel;
            /*
            UInt16 MaximumCurrentInMA2  :12;
            UInt16 CfaPowerMode1Disabled  :1;
            UInt16 CfaPowerMode1Required  :1;
            UInt16 Reserved0  :1;
            UInt16 Word160Supported  :1;
            */

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public ushort[] wReservedForCfa161;
            public ushort wSupportsTrim;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public ushort[] wReservedForCfa170;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
            public ushort[] wCurrentMediaSerialNumber;
            public ushort wReserved206;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ushort[] wReserved207;

            public ushort wBlockAlignment;
            /*
            UInt16 AlignmentOfLogicalWithinPhysical  :14;
            UInt16 Word209Supported  :1;
            UInt16 Reserved0  :1;
            */

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ushort[] wWriteReadVerifySectorCountMode3Only;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public ushort[] wWriteReadVerifySectorCountMode2Only;

            public ushort wNVCacheCapabilities;                     // <==
            /*
            UInt16 NVCachePowerModeEnabled  :1;
            UInt16 Reserved0  :3;
            UInt16 NVCacheFeatureSetEnabled  :1;
            UInt16 Reserved1  :3;
            UInt16 NVCachePowerModeVersion  :4;
            UInt16 NVCacheFeatureSetVersion  :4;
            */
            public ushort wNVCacheSizeLSW;
            public ushort wNVCacheSizeMSW;
            public ushort wNominalMediaRotationRate; //WORD 217: NOMINAL MEDIA ROTATION RATE 
            public ushort wReserved218;
            public ushort wNVCacheOptions;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 35)]
            public ushort[] wReserved220;         // WORD 220-253
            public byte bSignature;
            public byte bCheckSum;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 512)]
        public struct DEVICE_ATTR_DATA
        {
            public ushort wRevisionNum;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
            public IND_ATTR_DATA[] aIndAttrData;
            public byte bOfflineCollectStatus;      // 362 : Off-line data collection status
            public byte bSelftestExeStatus;         // 363 : Self-test execution status byte
            public ushort wOfflineCollectTotalTime;   // 364-365 : Total time in seconds to complete off-line data collection activity
            public byte bVendor1;                   // 366 : Vendor specific
            public byte bOfflineCollectCapability;  // 367 : Off-line data collection capability
            public ushort wSmartCapability;           // 368-369 : Smart capability
            public byte bErrLogCapability;          // 370 : Error logging capability ([7:1] => Reserved, [0] => 1 = Device error logging supported)
            public byte bVendor2;                   // 371 : Vendor specific
            public byte bShortPollingTime;          // 372 : Short self-test routine recommended polling time in minutes
            public byte bExtendedPollingTime;       // 373 : Extended self-test routine recommended polling time in minutes
            public byte bConveyancePollingTime;     // 374 : Conveyance self-test routine recommended polling time in minutes
            public ushort wExtendedPollingTime;          // 375-376: Extended self-test routine recommended polling time in minutes used if byte 373 is 0xFF. (ACS3)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
            public byte[] bReserved;                  // 377-385: Reserved
            //#ifndef FEATURE_ADATA_SMART
            //    byte abVendor3[122];                // 386-507: Vendor specific
            //#else
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public byte[] FirmwareVer;            // 386-395 : Firmware Version
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public byte[] bAdataProdName;         // 396-405 : ADATA product name code
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)]
            public byte[] bReserved2;             // 406-433 : Vendor specific
            public ushort wCustomerName;               // 434-435 : Customer name
            public ushort wProjectName;               // 436-437 : Project name
            public ushort wCompanyVersion;            // 438-439 : Company version number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public ushort[] wReserved;               // 440-445 : Reserved 3 words
            public Int32 dwFetureSelect;            // 446-449 : Features turn on select
            public Int32 dwHwFetureSelect;          // 450-453 : Hardware Features select
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 54)]
            public byte[] abVendor3;             // 454-507 : Vendor specific
            //#endif // ~ FEATURE_ADATA_SMART
            public ushort wRevisionNum2;               // 508-509 : Revision number
            public byte bVendor4;                   // 510 : Vendor specific
            public byte bChecksum;                  // 511 : Checksum

        }
        #endregion

        #region NVMe 結構體
        [StructLayout(LayoutKind.Sequential, Pack = 1)] // Total 512 Bytes
        public struct NVMe_SMART_DATA
        {


            /* 
            控制器狀態的嚴重警告
            bit     |   Definition
            00      |   如果設置為“1”，則可用的備用空間已經下降，低於門檻。
            01      |   如果設置為“1”，則溫度高於Max閾值，或低於Min閾值。溫度過熱
            02      |   如果設置為“1”，NAND 的可靠性降低，可以考慮維修換新。
            03      |   如果設置為“1”，則媒體已被置於只讀狀態模式。
            04      |   如果設置為“1”，斷電保護功能失效。家用固態硬盤，通常沒有此功能。因此可以忽略。
            07~05   |   保留
             */
            public byte Critical_Warning;                         //[0]   控制器狀態的嚴重警告
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Composite_Temperature;                  //[2:1] 複合溫度：包含與溫度（以度為單位）對應的值，開爾文代表控制器的當前複合溫度
            public byte Available_Spare;                          //[3]   當前固態硬盤可用於替換壞塊的保留備用塊，佔出廠時備用塊總數量的百分比。
            public byte Available_Spare_Threshold;                //[4]   備用空間的塊數量的百分比閥值。
            public byte Percentage_Used;                          //[5]   以寫入量佔廠商定義的總寫入壽命的百分比，此值與 TBW總寫入量指標有關。
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public byte[] Reserved_0;                             //[31:6]    保留區
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Data_Units_Read;                        //[47:32]   該項數值乘以1000後即為讀取的扇區(512 Byte)數量統計
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Data_Units_Written;                     //[63:48]   該項數值乘以1000後即為寫入的扇區(512 Byte)數量統計
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Host_Read_Commands;                     //[79:64]   Host端發過的總讀取命令數量
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Host_Write_Commands;                    //[95:80]   Host端發過的總寫入命令數量
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Controller_Busy_Time;                   //[111:96]  控制器忙碌的時間，單位[分鐘]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Power_Cycles;                           //[127:112] 上電次數
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Power_On_Hours;                         //[143:128] 總通電時間，不包含低功率狀態。單位[小時]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Unsafe_Shutdowns;                       //[159:144] 異常斷電次數
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Media_and_Data_Integrity_Errors;        //[175:160] 媒體數據，數據完整性驗證失敗次數。(ECC,CRC... 等等)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Number_of_Error_Information_Log_Entries;//[191:176] 錯誤發生的信息數量
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] Warning_Composite_Temperature_Time;     //[195:192] 異常溫度(高低於閥值)發生的累積時間。單位(分鐘)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] Critical_Composite_Temperature_Time;    //[199:196] 過熱臨界溫度時間
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Temperature_Sensor_1;                   //[201:200] 以下多個溫度傳感器的值(若存在)
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Temperature_Sensor_2;                   //[203:202]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Temperature_Sensor_3;                   //[205:204]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Temperature_Sensor_4;                   //[207:206]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Temperature_Sensor_5;                   //[209:208]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Temperature_Sensor_6;                   //[211:210]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Temperature_Sensor_7;                   //[213:212]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Temperature_Sensor_8;                   //[215:214]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 296)]
            public byte[] Reserved_1;                             //[511:216]
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NVME_IDENTIFY_DEVICE
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] PCI_Vendor_ID;                                            //  0~1
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] PCI_Subsystem_Vendor_ID;                                  //  2~3
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public Char[] Serial_Number;                                            //  4~23
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 40)]
            public Char[] Model_Number;                                             //  24~63
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public Char[] Firmware_Revision;                                        //  64~71
            public Byte Recommended_Arbitration_Burst;                              //  72
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public Byte[] IEEE_OUI_Identifier;                                      //  73~75
            public Byte Controller_Multi_Path_IO_and_Namespace_Sharing_Capabilities;//  76
            public Byte Maximum_Data_Transfer_Size;                                 //  77
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Controller_ID;                                            //  78~79
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Version;                                                  //  80~83   // Tertiary Version Number 80 Byte //  Minor Version Number 81 Byte // Major Version Number 82~83 Bytes
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] RTD3_Resume_Latency;                                      //  84~87
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] RTD3_Entry_Latency;                                       //  88~91
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Optional_Asynchronous_Events_Supported;                   //  92~95
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Controller_Attributes;                                    //  96~99
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Read_Recovery_Levels_Supported;                           //  100~101
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 9)]
            public Byte[] Reserved_0;                                               //  102~110
            public Byte Controller_Type;                                            //  111
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public Byte[] FRU_Globally_Unique_Identifier;                           //  112~127
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Command_Retry_Delay_Time_1;                               //  128~129
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Command_Retry_Delay_Time_2;                               //  130~131
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Command_Retry_Delay_Time_3;                               //  132~133
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 106)]
            public Byte[] Reserved_1;                                               //  134~239
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public Byte[] Refer_to_the_NVMe_Management_Interface_Specification_for_definition;  //  240~255
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Optional_Admin_Command_Support;                           //  256~257
            public Byte Abort_Command_Limit;                                        //  258
            public Byte Asynchronous_Event_Request_Limit;                           //  259
            public Byte Firmware_Updates;                                           //  260
            public Byte Log_Page_Attributes;                                        //  261
            public Byte Error_Log_Page_Entries;                                     //  262
            public Byte Number_of_Power_States_Support;                             //  263
            public Byte Admin_Vendor_Specific_Command_Configuration;                //  264
            public Byte Autonomous_Power_State_Transition_Attributes;               //  265，是否支持自主電源狀態轉換功能(APSTA 功能)。
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Warning_Composite_Temperature_Threshold;                  //  266~267
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Critical_Composite_Temperature_Threshold;                 //  268~269
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Maximum_Time_for_Firmware_Activation;                     //  270~271
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Host_Memory_Buffer_Preferred_Size;                        //  272~275
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Host_Memory_Buffer_Minimum_Size;                          //  276~279
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public Byte[] Total_NVM_Capacity;                                       //  280~295
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public Byte[] Unallocated_NVM_Capacity;                                 //  296~311
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Replay_Protected_Memory_Block_Support;                    //  312~315
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Extended_Device_Self_test_Time;                           //  316~317
            public Byte Device_Self_test_Options;                                   //  318
            public Byte Firmware_Update_Granularity;                                //  319
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Keep_Alive_Support;                                       //  320~321
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Host_Controlled_Thermal_Management_Attributes;            //  322~323
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Minimum_Thermal_Management_Temperature;                   //  324~325
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Maximum_Thermal_Management_Temperature;                   //  326~327
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Sanitize_Capabilities;                                    //  328~331
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Host_Memory_Buffer_Minimum_Descriptor_Entry_Size;         //  332~335
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Host_Memory_Maximum_Descriptors_Entries;                  //  336~337
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] NVM_Set_Identifier_Maximum;                               //  338~339
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Endurance_Group_Identifier_Maximum;                       //  340~341
            public Byte ANA_Transition_Time;                                        //  342
            public Byte Asymmetric_Namespace_Access_Capabilities;                   //  343
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] ANA_Group_Identifier_Maximum;                             //  344~347
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Number_of_ANA_Group_Identifiers;                          //  348~351
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Persistent_Event_Log_Size;                                //  352~355
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 156)]
            public Byte[] Reserved_2;                                               //  356~511
            public Byte Submission_Queue_Entry_Size;                                //  512
            public Byte Completion_Queue_Entry_Size;                                //  513
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Maximum_Outstanding_Commands;                             //  514~515
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Number_of_Namespaces;                                     //  516~519
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Optional_NVM_Command_Support;                             //  520~521
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Fused_Operation_Support;                                  //  522~523
            public Byte Format_NVM_Attributes;                                      //  524，該NVMe 設備支援的 Format Erase 功能，詳細請看 Spec。
            public Byte Volatile_Write_Cache;                                       //  525
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Atomic_Write_Unit_Normal;                                 //  526~527
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Atomic_Write_Unit_Power_Fail;                             //  528~529
            public Byte NVM_Vendor_Specific_Command_Configuration;                  //  530
            public Byte Namespace_Write_Protection_Capabilities;                    //  531
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Atomic_Compare_Write_Unit;                                //  532~533
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Reserved_3;                                               //  534~535
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] SGL_Support;                                              //  536~539
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public Byte[] Maximum_Number_of_Allowed_Namespaces;                     //  540~543
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 224)]
            public Byte[] Reserved_4;                                               //  544~767
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public Byte[] NVM_Subsystem_NVMe_Qualified_Name;                        //  768~1023
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 768)]
            public Byte[] Reserved_5;                                               //  1024~1791
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
            public Byte[] Refer_to_the_NVMe_over_Fabrics_specification;             //  1792~2047
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_0_Descriptor;                                 //  2048~2079
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_1_Descriptor;                                 //  2080~2111
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_2_Descriptor;                                 //  2112~2143
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_3_Descriptor;                                 //  2144~2175
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_4_Descriptor;                                 //  2176~2207
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_5_Descriptor;                                 //  2208~2239
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_6_Descriptor;                                 //  2240~2271
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_7_Descriptor;                                 //  2272~2303
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_8_Descriptor;                                 //  2304~2335
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_9_Descriptor;                                 //  2336~2367
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_10_Descriptor;                                //  2368~2399
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_11_Descriptor;                                //  2400~2431
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_12_Descriptor;                                //  2432~2463
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_13_Descriptor;                                //  2464~2495
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_14_Descriptor;                                //  2496~2527
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_15_Descriptor;                                //  2528~2559
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_16_Descriptor;                                //  2560~2591
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_17_Descriptor;                                //  2592~2623
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_18_Descriptor;                                //  2624~2655
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_19_Descriptor;                                //  2656~2687
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_20_Descriptor;                                //  2688~2719
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_21_Descriptor;                                //  2720~2751
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_22_Descriptor;                                //  2752~2783
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_23_Descriptor;                                //  2784~2815
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_24_Descriptor;                                //  2816~2847
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_25_Descriptor;                                //  2848~2879
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_26_Descriptor;                                //  2880~2911
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_27_Descriptor;                                //  2912~2943
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_28_Descriptor;                                //  2944~2975
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_29_Descriptor;                                //  2976~3007
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_30_Descriptor;                                //  3008~3039
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public Byte[] Power_State_31_Descriptor;                                //  3040~3071
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
            public Byte[] Vendor_Specific;                                          //  3072~4095
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NVME_IDENTIFY_NAMESPACE_DEVICE
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Namespace_Size;                                               // 0~7
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Namespace_Capacity;                                           // 8~15
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Namespace_Utilization;                                        // 16~23
            public byte Namespace_Features;                                             // 24
            public byte Number_Of_LBA_Formats;                                          // 25
            public byte Formatted_LBA_Size;                                             // 26
            public byte Metadata_Capabilities;                                          // 27
            public byte End_to_end_Data_Protection_Capabilities;                        // 28
            public byte End_to_end_Data_Protection_Type_Settings;                       // 29
            public byte Namespace_Multi_path_IO_and_Namespace_Sharing_Capabilities;     // 30
            public byte Reservation_Capabilities;                                       // 31
            public byte Format_Progress_Indicator;                                      // 32
            public byte Deallocate_Logical_Block_Features;                              // 33
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Atomic_Write_Unit_Normal;                           // 34~35
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Atomic_Write_Unit_Power_Fail;                       // 36~37
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Atomic_Compare_Write_Unit;                          // 38~39
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Atomic_Boundary_Size_Normal;                        // 40~41
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Atomic_Boundary_Offset;                             // 42~43
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Atomic_Boundary_Size_Power_Fail;                    // 44~45
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Optimal_IO_Boundary;                                // 46~47
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] NVM_Capacity;                                                 // 48~63
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Preferred_Write_Granularity;                        // 64~65
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Preferred_Write_Alignment;                          // 66~67
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Preferred_Deallocate_Granularity;                   // 68~69
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Preferred_Deallocate_Alignment;                     // 70~71
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Namespace_Optimal_Write_Size;                                 // 72~73
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 18)]
            public byte[] Reserved_0;                                                   // 74~91
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] ANA_Group_Identifier;                                         // 92~95
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] Reserved_1;                                                   // 96~98
            public byte Namespace_Attributes;                                           // 99
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] NVM_Set_Identifier;                                           // 100~101
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public byte[] Endurance_Group_Identifier;                                   // 102~103
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Namespace_Globally_Unique_Identifier;                         // 104~119
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] IEEE_Extended_Unique_Identifier;                              // 120~127
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_0_Support;                                         // 128~131
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_1_Support;                                         // 132~135
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_2_Support;                                         // 136~139
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_3_Support;                                         // 140~143
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_4_Support;                                         // 144~147
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_5_Support;                                         // 148~151
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_6_Support;                                         // 152~155
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_7_Support;                                         // 156~159
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_8_Support;                                         // 160~163
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_9_Support;                                         // 164~167
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_10_Support;                                        // 168~171
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_11_Support;                                        // 172~175
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_12_Support;                                        // 176~179
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_13_Support;                                        // 180~183
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_14_Support;                                        // 184~187
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public byte[] LBA_Format_15_Support;                                        // 188~191
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 192)]
            public byte[] Reserved_2;                                                   // 192~383
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3712)]
            public byte[] Vendor_Specific;                                              // 384~4095
        };
        #endregion

        #region SCSI 命令結構體
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SCSI_ADDRESS
        {
            UInt32 Length;
            Char PortNumber;
            Char PathId;
            Char TargetId;
            Char Lun;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct SRB_IO_CONTROL
        {
            internal Int32 HeaderLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            internal Char[] Signature;
            internal Int32 Timeout;
            internal Int32 ControlCode;
            internal Int32 ReturnCode;
            internal Int32 Length;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]    // change the packing, size is then 44, and alignments change
        public struct NVME_PASS_THROUGH_IOCTL
        {
            internal SRB_IO_CONTROL SrbIoCtrl;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE)]
            internal Int32[] VendorSpecific;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NVME_IOCTL_CMD_DW_SIZE)]
            internal UInt32[] NVMeCmd;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = NVME_IOCTL_COMPLETE_DW_SIZE)]
            internal Int32[] CplEntry;
            internal Int32 Direction;
            internal Int32 QueueId;
            internal Int32 DataBufferLen;
            internal Int32 MetaDataLen;
            internal Int32 ReturnBufferLen;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
            internal Byte[] DataBuffer;
        };
        #region USB Model Control 定義相關
        [StructLayout(LayoutKind.Sequential, Pack = 4)]    // change the packing, size is then 44, and alignments change
        public struct SCSI_PASS_THROUGH_DIRECT
        {
            public short Length;
            public byte ScsiStatus;
            public byte PathId;
            public byte TargetId;
            public byte Lun;
            public byte CdbLength;
            public byte SenseInfoLength;
            public byte DataIn;
            public int DataTransferLength;
            public int TimeOutValue;
            public IntPtr DataBufferOffset;
            public uint SenseInfoOffset;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Cdb;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT
        {
            public SCSI_PASS_THROUGH_DIRECT Spt;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] SenseBuf;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
            public byte[] DataBuf;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT
        {
            public SCSI_PASS_THROUGH_DIRECT Spt;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] SenseBuf;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
            public UInt32[] DataBuf_Alias_UInt32;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT
        {
            public SCSI_PASS_THROUGH_DIRECT Spt;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
            public byte[] SenseBuf;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
            public byte[] DataBuf;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT
        {
            public SCSI_PASS_THROUGH_DIRECT Spt;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
            public byte[] SenseBuf;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
            public UInt32[] DataBuf_Alias_UInt32;
        }
        #endregion
        #endregion

        #region Storage 命令結構體
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TStoragePropertyQuery
        {
            public TStoragePropertyId PropertyId;
            public TStorageQueryType QueryType;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TStorageProtocolSpecificData
        {
            public TStroageProtocolType ProtocolType;
            public Int32 DataType;
            public Int32 ProtocolDataRequestValue;
            public UInt32 ProtocolDataRequestSubValue;
            public Int32 ProtocolDataOffset;
            public Int32 ProtocolDataLength;
            public Int32 FixedProtocolReturnData;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public Int32[] Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TStorageQueryWithBuffer
        {
            public TStoragePropertyQuery Query;
            public TStorageProtocolSpecificData ProtocolSpecific;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
            public Byte[] Buffer;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TStorageQueryWithBuffer_564
        {
            public TStoragePropertyQuery Query;
            public TStorageProtocolSpecificData ProtocolSpecific;
            public NVME_DEVICE_SELF_TEST_LOG aNVME_DEVICE_SELF_TEST_LOG;
        }

        [StructLayoutAttribute(LayoutKind.Explicit, Pack = 1)]
        public struct NVME_COMMAND
        {
            [FieldOffset(0)]
            public UInt32 CDW0; //  Byte 0~3

            [FieldOffset(4)]
            public UInt32 NSID; //  Byte 4~7

            [FieldOffset(8)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public UInt32[] Reserved0;  //  Byte 8~15

            [FieldOffset(16)]
            public UInt64 MPTR; //  Byte 16~23

            [FieldOffset(24)]
            public UInt64 PRP1; //  Byte 24~31

            [FieldOffset(32)]
            public UInt64 PRP2; //  Byte 32~39

            [FieldOffset(40)]
            public UInt32 CDW10;    //  Byte 40~43

            [FieldOffset(44)]
            public UInt32 CDW11;    //  Byte 44~47

            [FieldOffset(48)]
            public UInt32 CDW12;    //  Byte 48~51

            [FieldOffset(52)]
            public UInt32 CDW13;    //  Byte 52~55

            [FieldOffset(56)]
            public UInt32 CDW14;    //  Byte 56~59

            [FieldOffset(60)]
            public UInt32 CDW15;    //  Byte 60~63
        }

        /// <summary>
        /// Vendor Specific Command
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct STORAGE_PROTOCOL_COMMAND
        {
            /// <summary>
            /// 此結構的版本。這應該設置為STORAGE_PROTOCOL_STRUCTURE_VERSION。
            /// </summary>
            public UInt32 Version;

            /// <summary>
            /// 這個結構的大小。這應該設置為 sizeof( STORAGE_PROTOCOL_COMMAND )。
            /// </summary>
            public UInt32 Length;

            /// <summary>
            /// 協議類型，類型為STORAGE_PROTOCOL_TYPE
            /// </summary>
            public TStroageProtocolType ProtocolType;

            /// <summary>
            /// 為此請求設置的標誌。以下是有效標誌。 => STORAGE_PROTOCOL_COMMAND_FLAG_ADAPTER_REQUEST	此標誌指示以適配器而不是設備為目標的請求。
            /// </summary>
            public UInt32 Flags;

            /// <summary>
            /// 對存儲設備發出的請求的狀態。在 Windows 10 中，可能的值包括：
            /// STORAGE_PROTOCOL_STATUS_PENDING	請求待處理。
            /// STORAGE_PROTOCOL_STATUS_SUCCESS	請求已成功完成。
            /// STORAGE_PROTOCOL_STATUS_ERROR	請求遇到錯誤。
            /// STORAGE_PROTOCOL_STATUS_INVALID_REQUEST	請求無效。
            /// STORAGE_PROTOCOL_STATUS_NO_DEVICE	設備無法發出請求。
            /// STORAGE_PROTOCOL_STATUS_BUSY	設備正忙於處理請求。
            /// STORAGE_PROTOCOL_STATUS_DATA_OVERRUN	設備在處理請求時遇到數據溢出。
            /// STORAGE_PROTOCOL_STATUS_INSUFFICIENT_RESOURCES	由於資源不足，設備無法完成請求。
            /// STORAGE_PROTOCOL_STATUS_NOT_SUPPORTED	不支持該請求。
            /// </summary>
            public UInt32 ReturnStatus;

            /// <summary>
            /// 此請求的錯誤代碼。這是可選設置的。
            /// </summary>
            public Int32 ErrorCode;

            /// <summary>
            /// 命令的長度。調用者必須設置一個非零值。
            /// </summary>
            public UInt32 CommandLength;

            /// <summary>
            /// 錯誤緩衝區的長度。這是可選的設置，可以設置為 0。
            /// </summary>
            public UInt32 ErrorInfoLength;

            /// <summary>
            /// 要傳輸到設備的緩衝區的大小。這僅與 WRITE 請求一起使用。
            /// </summary>
            public UInt32 DataToDeviceTransferLength;

            /// <summary>
            /// 這是要從設備傳輸的緩衝區的大小。這僅與 READ 請求一起使用。
            /// </summary>
            public UInt32 DataFromDeviceTransferLength;

            /// <summary>
            /// 在超時之前等待設備多長時間。這是以秒為單位設置的。
            /// </summary>
            public Int32 TimeOutValue;

            /// <summary>
            /// 錯誤緩衝區的偏移量。這必須是指針對齊的。
            /// </summary>
            public UInt32 ErrorInfoOffset;

            /// <summary>
            /// 要傳輸到設備的緩衝區的偏移量。這必須是指針對齊的，並且僅用於 WRITE 請求。
            /// </summary>
            public UInt32 DataToDeviceBufferOffset;

            /// <summary>
            /// 要從設備傳輸的緩衝區的偏移量。這必須是指針對齊的，並且僅用於 READ 請求。
            /// </summary>
            public UInt32 DataFromDeviceBufferOffset;

            /// <summary>
            /// 與命令一起傳遞的特定於命令的數據。這取決於來自驅動程序的命令，並且是可選設置的。
            /// </summary>
            public UInt32 CommandSpecific;

            /// <summary>
            /// 保留供將來使用。
            /// </summary>
            public Int32 Reserved0;

            /// <summary>
            /// 返回數據。這是可選設置的。某些協議（例如 NVMe）可能會返回少量數據（來自完成隊列條目的 DWORD0），而無需單獨的設備數據傳輸。
            /// </summary>
            public Int32 FixedProtocolReturnData;

            /// <summary>
            /// 保留供將來使用。
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public Int32[] Reserved1;

            /// <summary>
            /// 要傳遞到設備的特定於供應商的命令。
            /// 長度大小，受到此結構體的 CommandLength 長度影響，但不知如何在 宣告的結構體裡面，動態變動大小。因此就目前需求先寫死。
            /// 在 C 中，可變大小的數組被聲明為a[1]或a[ANYSIZE_ARRAY]，其中ANYSIZE_ARRAY定義為1。然後它就像它更大一樣被使用。
            /// </summary>
            public NVME_COMMAND Command;
        }

        /// <summary>
        /// NVME_LOG_PAGE_DEVICE_SELF_TEST. Size: 564 bytes
        /// </summary>
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct NVME_DEVICE_SELF_TEST_LOG
        {
            public static Hashtable ParserLog(NVME_DEVICE_SELF_TEST_LOG _NVME_DEVICE_SELF_TEST_LOG)
            {
                Hashtable tab = new Hashtable();
                int currentOperation = _NVME_DEVICE_SELF_TEST_LOG.aCurrentOperation.Status;
                int currentCompletion = _NVME_DEVICE_SELF_TEST_LOG.aCurrentCompletion.CompletePercent;
                var first_Device_Self_test_Status_Bits = new BitArray(new Byte[] { _NVME_DEVICE_SELF_TEST_LOG.aNVME_DEVICE_SELF_TEST_RESULT_DATA[0].Device_Self_test_Status });
                int first_Completed_Without_Error = first_Device_Self_test_Status_Bits.CopySlice(0, 4).GetInt16FromBitArray();
                int first_Operation = first_Device_Self_test_Status_Bits.CopySlice(4, 4).GetInt16FromBitArray();
                tab.Add(@"currentOperation", currentOperation);
                tab.Add(@"currentCompletion", currentCompletion);
                tab.Add(@"first_Completed_Without_Error", first_Completed_Without_Error);
                tab.Add(@"first_Operation", first_Operation);
                return tab;
            }

            public static Hashtable ParserLog(IntPtr data)
            {
                NVMe_Access.NVME_DEVICE_SELF_TEST_LOG log = (NVMe_Access.NVME_DEVICE_SELF_TEST_LOG)Marshal.PtrToStructure(data, typeof(NVMe_Access.NVME_DEVICE_SELF_TEST_LOG));
                return ParserLog(log);
            }

            /// <summary>
            /// This field defines the current device self-test operation. (該字段定義當前設備自檢操作。)
            /// Value 0h    =>  No device self-test operation in progress   (沒有正在進行的設備自檢操作)
            /// Value 1h    =>  Short device self-test operation in progres (正在進行短設備自檢操作)
            /// Value 2h    =>  Extended device self-test operation in progress (正在進行擴展設備自檢操作)
            /// Value 3h~Dh =>  Reserved
            /// Value Eh    =>  Vendor specific
            /// Value Fh    =>  Reserved
            /// </summary>
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct CurrentOperation
            {
                public Byte Status;
            }

            /// <summary>
            /// This field defines the completion status of the current device self-test (該字段定義了當前設備自檢的完成狀態)
            /// Bit 6~0  indicates the percentage of the device self-test operation that is complete (表示設備自檢操作完成的百分比)
            /// </summary>
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct CurrentCompletion
            {
                public Byte CompletePercent;
            }

            public CurrentOperation aCurrentOperation;

            public CurrentCompletion aCurrentCompletion;

            /// <summary>
            /// 保留供將來使用。
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Reserved;

            /// <summary>
            /// Self-test Result Data Structure
            /// </summary>
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct NVME_DEVICE_SELF_TEST_RESULT_DATA
            {
                /// <summary>
                /// This field indicates the device self-test code and the status of the operation. (該字段指示設備自檢代碼和狀態手術。)
                /// Bit 0~3 =>  Result of Device Self-Test operation of this particular result data (該自檢結果數據表示設備自檢操作的結果結構描述)
                /// 0h  =>  Operation completed without error
                /// 1h  =>  Operation was aborted by a Device Self-test command
                /// 2h  =>  Operation was aborted by a Controller Level Reset
                /// 3h  =>  Operation was aborted due to a removal of a namespace from the namespace inventory
                /// 4h  =>  Operation was aborted due to the processing of a Format NVM command
                /// 5h  =>  A fatal error or unknown test error occurred while the controller was executing the device self-test operation and the operation did not complete
                /// 6h  =>  Operation completed with a segment that failed and the segment that failed is not known
                /// 7h  =>  Operation completed with one or more failed segments and the first segment that failed is indicated in the Segment Number field
                /// 8h  =>  Operation was aborted for unknown reason
                /// 9h  =>  Operation was aborted due to a sanitize operation
                /// Fh  =>  Entry not used (does not contain a test result)
                /// Bit 4~7 =>   Self-Test code value that was specified in command. (表示設備自檢命令中指定的自檢代碼值該自檢結果數據結構描述的設備自檢操作開始。)
                /// 0h  =>  Reserved
                /// 1h  =>  Short device self-test operation
                /// 2h  =>  Extended device self-test operation
                /// 3h~Dh   =>  Reserved
                /// Eh  =>  Vendor specific
                /// Fh  =>  Reserved
                /// </summary>
                public Byte Device_Self_test_Status;

                /// <summary>
                /// Indicates the first segment that failure occured
                /// </summary>
                public Byte SegmentNumber;

                /// <summary>
                /// This field indicates the diagnostic failure information that is reported. (該字段表示診斷失敗信息，即報導。)
                /// Bit 0   =>  NSIDValid   =>  If set to 1, the contents of Namespace Identifier field is valid
                /// Bit 1   =>  FLBAValid   =>  If set to 1, the contents of Failing LBA field is valid
                /// Bit 2   =>  SCTValid    =>  If set to 1, the contents of Status Code Type field is valid
                /// Bit 3   =>  SCValid     =>  If set to 1, the contents of Status Code field is valid
                /// Bit 4~8 =>  Reserved
                /// </summary>
                public Byte ValidDiagnostics;

                public Byte Reserved;

                /// <summary>
                /// Power On Hours, when test operation was completed/aborted
                /// </summary>
                public UInt64 PowerOnHours;

                /// <summary>
                /// Namespace Identifier. Only valid if NSIDValid is set
                /// </summary>
                public UInt32 NamespaceIdentifier;

                /// <summary>
                /// Failed LBA which caused test to fail. Only valid if FLBAValid is set
                /// </summary>
                public UInt64 FailingLBA;

                /// <summary>
                /// Additional information related to errors/conditions. Only valid if SCTValid is set
                /// Bit 0~2 =>  Additional information related to errors/conditions. Only valid if SCTValid is set
                /// Bit 3~7 =>  Reserved
                /// </summary>
                public Byte StatusCodeType;

                /// <summary>
                /// Additional information related to errors/conditons. Only valid if SCValid is set
                /// </summary>
                public Byte StatusCode;

                /// <summary>
                /// Vendor Specific
                /// </summary>
                public UInt16 VendorSpecific;
            }

            /// <summary>
            /// Self-test Result Data 20 Array
            /// </summary>
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public NVME_DEVICE_SELF_TEST_RESULT_DATA[] aNVME_DEVICE_SELF_TEST_RESULT_DATA;
        }
        #endregion
        #endregion

        #region ENUM

        /**
         * 參考 CDI的廠商資訊寫法
         * */
        public enum VENDOR_ID
        {
            HDD_GENERAL = 0,
            SSD_GENERAL = 1,
            SSD_VENDOR_MTRON = 2,
            SSD_VENDOR_INDILINX = 3,
            SSD_VENDOR_JMICRON = 4,
            SSD_VENDOR_INTEL = 5,
            SSD_VENDOR_SAMSUNG = 6,
            SSD_VENDOR_SANDFORCE = 7,
            SSD_VENDOR_MICRON = 8,
            SSD_VENDOR_OCZ = 9,
            HDD_SSD_VENDOR_SEAGATE = 10,
            HDD_VENDOR_WESTERN_DIGITAL = 11,
            SSD_VENDOR_PLEXTOR = 12,
            SSD_VENDOR_SANDISK = 13,
            SSD_VENDOR_OCZ_VECTOR = 14,
            HDD_SSD_VENDOR_TOSHIBA = 15,
            SSD_VENDOR_CORSAIR = 16,
            SSD_VENDOR_KINGSTON = 17,
            SSD_VENDOR_MICRON_MU02 = 18,
            SSD_VENDOR_NVME = 19,
            SSD_VENDOR_REALTEK = 20,
            SSD_VENDOR_SKhynix = 21,
            SSD_VENDOR_MAX = 99,

            VENDOR_UNKNOWN = 0x0000,
            USB_VENDOR_BUFFALO = 0x0411,
            USB_VENDOR_IO_DATA = 0x04BB,
            USB_VENDOR_LOGITEC = 0x0789,
            USB_VENDOR_INITIO = 0x13FD,
            USB_VENDOR_SUNPLUS = 0x04FC,
            USB_VENDOR_JMICRON = 0x152D,
            USB_VENDOR_CYPRESS = 0x04B4,
            USB_VENDOR_OXFORD = 0x0928,
            USB_VENDOR_PROLIFIC = 0x067B,
            USB_VENDOR_REALTEK = 0x0BDA,
            USB_VENDOR_ALL = 0xFFFF,

            // 新增自定義部分，非 CDI來的以下
            USB_VENDOR_ADATA = 0x125F,
            USB_VENDOR_ASMEDIA = 0x174C,
            USB_VENDOR_ELECOM = 0x056E,
        }

        public enum COMMAND_TYPE
        {
            CMD_TYPE_UNKNOWN = 0,
            CMD_TYPE_PHYSICAL_DRIVE,
            CMD_TYPE_SCSI_MINIPORT,
            CMD_TYPE_SILICON_IMAGE,
            CMD_TYPE_SAT,               // SAT = SCSI_ATA_TRANSLATION
            CMD_TYPE_SUNPLUS,
            CMD_TYPE_IO_DATA,
            CMD_TYPE_LOGITEC1,
            CMD_TYPE_LOGITEC2,
            CMD_TYPE_JMICRON,
            CMD_TYPE_ASMEDIA,
            CMD_TYPE_CYPRESS,
            CMD_TYPE_PROLIFIC,          // Not imprement
            CMD_TYPE_CSMI,              // CSMI = Common Storage Management Interface
            CMD_TYPE_CSMI_PHYSICAL_DRIVE, // CSMI = Common Storage Management Interface 
            CMD_TYPE_WMI,

            CMD_TYPE_MAXIO,

            CMD_TYPE_NVME_SAMSUNG,
            CMD_TYPE_NVME_INTEL,
            CMD_TYPE_NVME_STORAGE_QUERY,
            CMD_TYPE_NVME_JMICRON,
            CMD_TYPE_NVME_ASMEDIA,
            CMD_TYPE_DEBUG,

            CMD_TYPE_NVME_REALTEK
        }

        public enum IO_CONTROL_CODE
        {
            DFP_SEND_DRIVE_COMMAND = 0x0007C084,
            DFP_RECEIVE_DRIVE_DATA = 0x0007C088,
            IOCTL_SCSI_MINIPORT = 0x0004D008,
            IOCTL_IDE_PASS_THROUGH = 0x0004D028, // 2000 or later
            IOCTL_ATA_PASS_THROUGH = 0x0004D02C, // XP SP2 and 2003 or later
        }

        #region Storage ENUM
        public enum TStoragePropertyId
        {
            StorageDeviceProperty = 0,
            StorageAdapterProperty,
            StorageDeviceIdProperty,
            StorageDeviceUniqueIdProperty,
            StorageDeviceWriteCacheProperty,
            StorageMiniportProperty,
            StorageAccessAlignmentProperty,
            StorageDeviceSeekPenaltyProperty,
            StorageDeviceTrimProperty,
            StorageDeviceWriteAggregationProperty,
            StorageDeviceDeviceTelemetryProperty,
            StorageDeviceLBProvisioningProperty,
            StorageDevicePowerProperty,
            StorageDeviceCopyOffloadProperty,
            StorageDeviceResiliencyProperty,
            StorageDeviceMediumProductType,
            StorageDeviceRpmbProperty,
            StorageDeviceIoCapabilityProperty = 48,
            StorageAdapterProtocolSpecificProperty,
            StorageDeviceProtocolSpecificProperty,
            StorageAdapterTemperatureProperty,
            StorageDeviceTemperatureProperty,
            StorageAdapterPhysicalTopologyProperty,
            StorageDevicePhysicalTopologyProperty,
            StorageDeviceAttributesProperty,
            StorageDeviceManagementStatus,
            StorageAdapterSerialNumberProperty,
            StorageDeviceLocationProperty,
            StorageDeviceNumaProperty,
            StorageDeviceZonedDeviceProperty,
            StorageDeviceUnsafeShutdownCount,
            StorageDeviceEnduranceProperty,
            StorageDeviceLedStateProperty,
            StorageDeviceSelfEncryptionProperty = 64,
            StorageFruIdProperty,
        }

        public enum TStorageQueryType
        {
            PropertyStandardQuery = 0,
            PropertyExistsQuery,
            PropertyMaskQuery,
            PropertyQueryMaxDefined
        }

        public enum TStroageProtocolType
        {
            ProtocolTypeUnknown = 0x00,
            ProtocolTypeScsi,
            ProtocolTypeAta,
            ProtocolTypeNvme,
            ProtocolTypeSd,
            ProtocolTypeProprietary = 0x7E,
            ProtocolTypeMaxReserved = 0x7F
        }

        public enum TStorageProtocolNVMeDataType
        {
            NVMeDataTypeUnknown = 0,
            NVMeDataTypeIdentify,
            NVMeDataTypeLogPage,
            NVMeDataTypeFeature,
        }

        //
        // Admin Command Set
        //
        public enum NVME_ADMIN_COMMANDS
        {

            NVME_ADMIN_COMMAND_DELETE_IO_SQ = 0x00,
            NVME_ADMIN_COMMAND_CREATE_IO_SQ = 0x01,
            NVME_ADMIN_COMMAND_GET_LOG_PAGE = 0x02,
            NVME_ADMIN_COMMAND_DELETE_IO_CQ = 0x04,
            NVME_ADMIN_COMMAND_CREATE_IO_CQ = 0x05,
            NVME_ADMIN_COMMAND_IDENTIFY = 0x06,
            NVME_ADMIN_COMMAND_ABORT = 0x08,
            NVME_ADMIN_COMMAND_SET_FEATURES = 0x09,
            NVME_ADMIN_COMMAND_GET_FEATURES = 0x0A,
            NVME_ADMIN_COMMAND_ASYNC_EVENT_REQUEST = 0x0C,
            NVME_ADMIN_COMMAND_NAMESPACE_MANAGEMENT = 0x0D,

            NVME_ADMIN_COMMAND_FIRMWARE_ACTIVATE = 0x10,
            NVME_ADMIN_COMMAND_FIRMWARE_COMMIT = 0x10,         // "Firmware Activate" command has been renamed to "Firmware Commit" command in spec v1.2
            NVME_ADMIN_COMMAND_FIRMWARE_IMAGE_DOWNLOAD = 0x11,
            NVME_ADMIN_COMMAND_DEVICE_SELF_TEST = 0x14,
            NVME_ADMIN_COMMAND_NAMESPACE_ATTACHMENT = 0x15,

            NVME_ADMIN_COMMAND_DIRECTIVE_SEND = 0x19,
            NVME_ADMIN_COMMAND_DIRECTIVE_RECEIVE = 0x1A,
            NVME_ADMIN_COMMAND_VIRTUALIZATION_MANAGEMENT = 0x1C,
            NVME_ADMIN_COMMAND_NVME_MI_SEND = 0x1D,
            NVME_ADMIN_COMMAND_NVME_MI_RECEIVE = 0x1E,

            NVME_ADMIN_COMMAND_DOORBELL_BUFFER_CONFIG = 0x7C,

            NVME_ADMIN_COMMAND_FORMAT_NVM = 0x80,
            NVME_ADMIN_COMMAND_SECURITY_SEND = 0x81,
            NVME_ADMIN_COMMAND_SECURITY_RECEIVE = 0x82,
            NVME_ADMIN_COMMAND_SANITIZE = 0x84,
            NVME_ADMIN_COMMAND_GET_LBA_STATUS = 0x86,

        }

        /// <summary>
        /// Parameters for NVME_ADMIN_COMMAND_GET_LOG_PAGE Command
        /// </summary>
        public enum NVME_LOG_PAGES
        {
            NVME_LOG_PAGE_ERROR_INFO = 0x01,
            NVME_LOG_PAGE_HEALTH_INFO = 0x02,
            NVME_LOG_PAGE_FIRMWARE_SLOT_INFO = 0x03,
            NVME_LOG_PAGE_CHANGED_NAMESPACE_LIST = 0x04,
            NVME_LOG_PAGE_COMMAND_EFFECTS = 0x05,
            NVME_LOG_PAGE_DEVICE_SELF_TEST = 0x06,
            NVME_LOG_PAGE_TELEMETRY_HOST_INITIATED = 0x07,
            NVME_LOG_PAGE_TELEMETRY_CTLR_INITIATED = 0x08,
            NVME_LOG_PAGE_ENDURANCE_GROUP_INFORMATION = 0x09,
            NVME_LOG_PAGE_PREDICTABLE_LATENCY_NVM_SET = 0x0A,
            NVME_LOG_PAGE_PREDICTABLE_LATENCY_EVENT_AGGREGATE = 0x0B,
            NVME_LOG_PAGE_ASYMMETRIC_NAMESPACE_ACCESS = 0x0C,
            NVME_LOG_PAGE_PERSISTENT_EVENT_LOG = 0x0D,
            NVME_LOG_PAGE_LBA_STATUS_INFORMATION = 0x0E,
            NVME_LOG_PAGE_ENDURANCE_GROUP_EVENT_AGGREGATE = 0x0F,

            NVME_LOG_PAGE_RESERVATION_NOTIFICATION = 0x80,
            NVME_LOG_PAGE_SANITIZE_STATUS = 0x81,

            NVME_LOG_PAGE_CHANGED_ZONE_LIST = 0xBF,
        }

        #endregion
        #endregion

        #region 工具區
        /// <summary>
        /// NVME_PASS_THROUGH_IOCTL 轉 Byte[]。
        /// </summary>
        /// <param name="aNVMeStruct">NVME_PASS_THROUGH_IOCTL 結構體</param>
        public static byte[] getBytes(NVME_PASS_THROUGH_IOCTL aNVMeStruct)
        {
            int size = Marshal.SizeOf(aNVMeStruct);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(aNVMeStruct, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        /// <summary>
        /// 建立 IO 連線。
        /// </summary>
        /// <param name="filename">'\\\\.\\PhysicalDrive{0}' or '\\\\.\\SCSI1:'</param>
        public static SafeFileHandle GetIoCtrlHandle(string filename)
        {
            return CreateFileW(filename,
                                    GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    IntPtr.Zero,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    IntPtr.Zero);
        }

        /// <summary>
        /// 磁碟 Index，轉 \\\\.\\PhysicalDrive{0} 輸出。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        public static string GetPhysicalDriveNamePath(int physicalDriveId)
        {
            return String.Format("\\\\.\\PhysicalDrive{0}", physicalDriveId);
        }

        /// <summary>
        /// 磁碟 SCSI_Path，轉 \\\\.\\PhysicalDrive{0} 輸出。
        /// 不建議使用
        /// </summary>
        /// <param name="SCSI_Path">磁碟 SCSI_Path</param>
        public static string GetPhysicalDriveNamePath_From_SCSI_Path(string SCSI_Path)
        {
            return SCSI_Path.Replace("\\\\.\\SCSI", "\\\\.\\PhysicalDrive");
        }

        /// <summary>
        /// SATA 在用的重整字串輸出。
        /// </summary>
        /// <param name="atastring">原始字串</param>
        /// <param name="byteSwitch">是否顛倒字元</param>
        public static string AdjustATAStringToString(string atastring, bool byteSwitch)
        {

            int num = atastring.Length / 2;
            int j = 0;
            char[] array = atastring.ToCharArray();
            if (byteSwitch)
            {
                for (int i = 0; i < num; i++)
                {
                    char temp = array[j];
                    array[j] = array[j + 1];
                    array[j + 1] = temp;
                    j = j + 2;
                }
            }

            return new string(array);

        }
        #endregion
    }

    /// <summary>
    /// SATA 對外界面。
    /// </summary>
    public class SATA_Access : ExternBase
    {
        #region 單例處理
        //定義一個靜態變數來保存類的實體
        private static volatile SATA_Access _instance;

        //定義一個標識確保執行緒同步
        private static readonly object locker = new object();

        //定義私有建構式，使外界不能創建該類實體，
        private SATA_Access()
        {
            //Console.WriteLine("Singleton物件已被創建，");
        }

        /// <summary>
        /// 定義公有屬性來提供全域訪問點，
        /// </summary>
        public static SATA_Access Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (locker)
                    {
                        // 如果類的實體不存在則創建，否則直接回傳
                        if (_instance == null)
                        {
                            _instance = new SATA_Access();
                        }
                    }
                }
                return _instance;
            }
        }
        #endregion

        /// <summary>
        /// SATA USB Get Identify Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 SATA Identify 結構體存放指標</param>
        /// <param name="ModelControl">傳入 SCSIVendor 字串，可為空字串。</param>
        /// <param name="USB_VendorID">USB VID</param>
        /// <param name="USB_ProductID">USB PID</param>
        public bool SATA_USB_Identify_ReadData(int physicalDriveId, IntPtr pbuffer, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            COMMAND_TYPE aCommandType = GetModelControl(ModelControl, USB_VendorID, USB_ProductID);
            SATA_Cmd cmd = SATA_Cmd.Instance;

            if (aCommandType != COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                switch (aCommandType)
                {
                    case COMMAND_TYPE.CMD_TYPE_ASMEDIA:
                        {
                            return cmd.SATA_USB_Identify_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_SAT:
                        {
                            // 標準的 USB to SATA SCSI Command
                            return cmd.SATA_USB_Identify_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    default:
                        {
                            return false;
                        }
                        break;
                }
            }
            else
            {
                Track.WriteLine("SATA_USB_Identify_ReadData 不支援的 Control Model = {0}", ModelControl);
                return false;
            }
        }

        /// <summary>
        /// SATA USB Get SMART Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 SATA Identify 結構體存放指標</param>
        /// <param name="ModelControl">傳入 SCSIVendor 字串，可為空字串。</param>
        /// <param name="USB_VendorID">USB VID</param>
        /// <param name="USB_ProductID">USB PID</param>
        public bool SATA_USB_SMART_ReadData(int physicalDriveId, IntPtr pbuffer, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            COMMAND_TYPE aCommandType = GetModelControl(ModelControl, USB_VendorID, USB_ProductID);
            SATA_Cmd cmd = SATA_Cmd.Instance;

            if (aCommandType != COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                switch (aCommandType)
                {
                    case COMMAND_TYPE.CMD_TYPE_ASMEDIA:
                        {
                            return cmd.SATA_USB_GetSmartAttribute_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_SAT:
                        {
                            // 標準的 USB to SATA SCSI Command
                            return cmd.SATA_USB_GetSmartAttribute_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    default:
                        {
                            return false;
                        }
                        break;
                }
            }
            else
            {
                Track.WriteLine("SATA_USB_SMART_ReadData 不支援的 Control Model = {0}", ModelControl);
                return false;
            }
        }

        /// <summary>
        /// SATA Maxio UnLock WriteProtect。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="tYPE">目前只支援 CMD_TYPE_MAXIO</param>
        public bool SATA_Custom_Products_UnLock_WriteProtect(int physicalDriveId, COMMAND_TYPE tYPE)
        {
            bool ret = false;
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            SATA_Cmd cmd = SATA_Cmd.Instance;
            switch (tYPE)
            {
                case COMMAND_TYPE.CMD_TYPE_MAXIO:
                    {
                        return cmd.SATA_UnLock_WriteProtect(devFileName, COMMAND_TYPE.CMD_TYPE_MAXIO);
                    }
                    break;
                default:
                    break;
            }
            return ret;
        }

        /// <summary>
        /// SATA ClearSmart。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="tYPE">目前只支援 CMD_TYPE_MAXIO</param>
        public bool SATA_ClearSmart(int physicalDriveId, COMMAND_TYPE tYPE)
        {
            bool ret = false;
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            SATA_Cmd cmd = SATA_Cmd.Instance;
            switch (tYPE)
            {
                case COMMAND_TYPE.CMD_TYPE_MAXIO:
                    {
                        return cmd.SATA_ClearSmart(devFileName, COMMAND_TYPE.CMD_TYPE_MAXIO);
                    }
                    break;
                default:
                    break;
            }
            return ret;
        }

        #region 工具區
        /// <summary>
        /// 判讀 USB 的 Model 是哪一家的。
        /// 目前不確定這寫法的萬用性，只是根據撈到的 "WMI Model" 資訊，進行判別分類。 
        /// </summary>
        private COMMAND_TYPE GetModelControl(string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            COMMAND_TYPE aCommandType = COMMAND_TYPE.CMD_TYPE_UNKNOWN;
            string tempModelControl = ModelControl.ToLower();

            if (tempModelControl.Contains(@"JMicron".ToLower()))
            {
                // JMicron USB Model
                aCommandType = COMMAND_TYPE.CMD_TYPE_JMICRON;
            }

            // 發生透過 ModelControl 資訊，無法識別廠商，進一步透過 USB VID判斷。
            if (aCommandType == COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                // 進一步透過，USB VID判斷
                try
                {
                    int tempUSB_VendorID = Int32.Parse(USB_VendorID, System.Globalization.NumberStyles.HexNumber);
                    int tempUSB_ProductID = Int32.Parse(USB_ProductID, System.Globalization.NumberStyles.HexNumber);

                    if (tempUSB_VendorID == (int)VENDOR_ID.USB_VENDOR_ASMEDIA)
                    {
                        // USB ASMedia
                        aCommandType = COMMAND_TYPE.CMD_TYPE_ASMEDIA;
                    }
                    else if (tempUSB_VendorID == (int)VENDOR_ID.USB_VENDOR_JMICRON)
                    {
                        aCommandType = COMMAND_TYPE.CMD_TYPE_SAT;
                    }
                    else
                    {
                        // 1. 因為 ADATA VID 底下，有各家用的USB裝置，因此無法當作依據判斷哪種命令。
                        // 2. 因為 ADATA 會幫廠商客製 USB外接裝置，因此VID 有機會被改成客製商的VID，因此也不準。
                        // 結論: 這類型都透過 MES資訊上 和 Default XML檔紀錄的，Bridge Control Name，去映射。
                        return BridgeControlName_MappingCommands.GetCommandType();

                    }


                }
                catch (Exception)
                {

                    aCommandType = COMMAND_TYPE.CMD_TYPE_UNKNOWN;
                }

            }

            return aCommandType;
        }

        /// <summary>
        /// 判讀 USB 的 裝置硬碟 是否為 SATA 設備。
        /// </summary>
        public bool SATA_USB_Device_Check(int physicalDriveId, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            bool isSATA = false;

            IntPtr identify_data = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));

            try
            {
                isSATA = SATA_USB_Identify_ReadData(physicalDriveId, identify_data, ModelControl, USB_VendorID, USB_ProductID); ;
            }
            catch (Exception ex)
            {
                Track.WriteLine(ex.ToString());
                isSATA = false;
            }
            finally
            {
                if (identify_data != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(identify_data);
                    identify_data = IntPtr.Zero;
                }
            }
            return isSATA;
        }
        #endregion
    }

    /// <summary>
    /// SATA 內部實作。
    /// </summary>
    public class SATA_Cmd : ExternBase
    {
        #region 單例處理
        //定義一個靜態變數來保存類的實體
        private static volatile SATA_Cmd _instance;

        //定義一個標識確保執行緒同步
        private static readonly object locker = new object();

        //定義私有建構式，使外界不能創建該類實體，
        private SATA_Cmd()
        {
            //Console.WriteLine("Singleton物件已被創建，");
        }

        /// <summary>
        /// 定義公有屬性來提供全域訪問點，
        /// </summary>
        public static SATA_Cmd Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (locker)
                    {
                        // 如果類的實體不存在則創建，否則直接回傳
                        if (_instance == null)
                        {
                            _instance = new SATA_Cmd();
                        }
                    }
                }
                return _instance;
            }
        }
        #endregion

        #region SATA 對外接口區
        public bool SATA_UnLock_WriteProtect(string filename, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_MAXIO)
            {
                return MaxioSATA_Onboard.UnLock_WriteProtect(filename);
            }

            return nRet;
        }

        public bool SATA_ClearSmart(string filename, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_MAXIO)
            {
                return MaxioSATA_Onboard.ClearSmart(filename);
            }

            return nRet;
        }
        #endregion

        #region SATA USB 對外接口區
        public bool SATA_USB_Identify_ReadData_Cmd(string filename, IntPtr identify_data, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_ASMEDIA)
            {
                return ASMediaSATA_Bridge.DoIdentifyDevice(filename, identify_data);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_SAT)
            {
                return SAT_SATA_Bridge.DoIdentifyDevice(filename, identify_data);
            }

            return nRet;
        }

        public bool SATA_USB_GetSmartAttribute_ReadData_Cmd(string filename, IntPtr smart_data, COMMAND_TYPE commandType)
        {
            bool nRet = false;
            if (commandType == COMMAND_TYPE.CMD_TYPE_ASMEDIA)
            {
                return ASMediaSATA_Bridge.GetSmartAttribute(filename, smart_data);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_SAT)
            {
                return SAT_SATA_Bridge.GetSmartAttribute(filename, smart_data);
            }
            return nRet;
        }

        #endregion

        #region Onboard
        private class MaxioSATA_Onboard : ExternBase
        {
            #region Maxio
            public static bool UnLock_WriteProtect(string filename)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;


                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_UNSPECIFIED;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 6;                //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0;                //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = 0xDA;                   //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 0x41;                   //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 0;                   //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = 0;                   //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = 0;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xE0;                // Device
                    sptwb.Spt.Cdb[9] = 0xEF;                //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================
                    Thread.Sleep(500);
                    //============== 第二階段  Start ====================================

                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 0x08;                //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0x0b;                //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = 0;                   //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 1;                   //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 0;                   //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = 0;                   //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = 0;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xE0;                // Device
                    sptwb.Spt.Cdb[9] = 0xEC;                //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    else
                    {
                        SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_resultTemp = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));
                        IntPtr pbuffer = IntPtr.Zero;
                        try
                        {
                            pbuffer = Marshal.AllocHGlobal(512);
                            Marshal.Copy(sptwb_resultTemp.DataBuf, 0, pbuffer, 512);
                            DeviceAccess.IDSECTOR identify = (DeviceAccess.IDSECTOR)Marshal.PtrToStructure(pbuffer, typeof(DeviceAccess.IDSECTOR));
                            string sSN = "", sModel = "";
                            sSN = AdjustATAStringToString(new string(identify.sSerialNumber), true).Trim();
                            sModel = AdjustATAStringToString(new string(identify.sModelNumber), true).Trim();
                        }
                        finally
                        {
                            if (pbuffer != IntPtr.Zero)
                            {
                                Marshal.FreeHGlobal(pbuffer);
                            }
                        }
                    }
                    //============== 第二階段  End ====================================
                    Thread.Sleep(500);
                    //============== 第三階段  Start ====================================

                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 0x16;                //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0x06;                //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = 0;                   //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 0x01;                   //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 0xFF;                   //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = 0x34;                   //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = 0x12;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xE0;                   // Device
                    sptwb.Spt.Cdb[9] = 0x88;                   //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    sptwb.DataBuf[0] = 0xFF;
                    sptwb.DataBuf[1] = 0xE5;
                    sptwb.DataBuf[2] = 0x42;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第三階段  End ====================================
                    Thread.Sleep(500);

                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));



                    if (bRet == true)
                    {
                        // 最終結果

                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool ClearSmart(string filename)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;


                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_UNSPECIFIED;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 6;                //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0;                //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = 0xDA;                   //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 0x41;                   //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 0;                   //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = 0;                   //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = 0;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xE0;                // Device
                    sptwb.Spt.Cdb[9] = 0xEF;                //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================
                    Thread.Sleep(500);
                    //============== 第二階段  Start ====================================

                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 0x08;                //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0x0b;                //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = 0;                   //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 1;                   //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 0;                   //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = 0;                   //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = 0;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xE0;                // Device
                    sptwb.Spt.Cdb[9] = 0xEC;                //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    else
                    {
                        SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_resultTemp = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));
                        IntPtr pbuffer = IntPtr.Zero;
                        try
                        {
                            pbuffer = Marshal.AllocHGlobal(512);
                            Marshal.Copy(sptwb_resultTemp.DataBuf, 0, pbuffer, 512);
                            DeviceAccess.IDSECTOR identify = (DeviceAccess.IDSECTOR)Marshal.PtrToStructure(pbuffer, typeof(DeviceAccess.IDSECTOR));
                            string sSN = "", sModel = "";
                            sSN = AdjustATAStringToString(new string(identify.sSerialNumber), true).Trim();
                            sModel = AdjustATAStringToString(new string(identify.sModelNumber), true).Trim();
                        }
                        finally
                        {
                            if (pbuffer != IntPtr.Zero)
                            {
                                Marshal.FreeHGlobal(pbuffer);
                            }
                        }
                    }
                    //============== 第二階段  End ====================================
                    Thread.Sleep(500);
                    //============== 第三階段  Start ====================================

                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 0x16;                //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0x06;                //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = 0;                   //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 0x01;                   //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 0xFF;                   //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = 0x34;                   //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = 0x12;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xE0;                   // Device
                    sptwb.Spt.Cdb[9] = 0x88;                   //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    sptwb.DataBuf[0] = 0xFF;
                    sptwb.DataBuf[1] = 0xE5;
                    sptwb.DataBuf[2] = 0x40;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第三階段  End ====================================
                    Thread.Sleep(500);

                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));



                    if (bRet == true)
                    {
                        // 最終結果

                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }
            #endregion
        }
        #endregion

        #region USB Bridge Control

        private class ASMediaSATA_Bridge : ExternBase
        {
            #region ASMedia
            public static bool DoIdentifyDevice(string filename, IntPtr sata_identufy_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (sata_identufy_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = IDENTIFY_BUFFER_SIZE;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 0x08;                //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0x0E;                //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = 0;                   //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 1;                   //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 0;                   //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = 0;                   //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = 0;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xA0;
                    sptwb.Spt.Cdb[9] = ID_CMD;     //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false || dwReturned != length)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, sata_identufy_data_ptr, Marshal.SizeOf(typeof(IDSECTOR)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool GetSmartAttribute(string filename, IntPtr sata_smart_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (sata_smart_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = READ_ATTRIBUTE_BUFFER_SIZE;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                                    //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 0x08;                                    //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0x0E;                                    //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = READ_ATTRIBUTES;                //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 1;                                       //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 1;                                       //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = SMART_CYL_LOW;                  //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = SMART_CYL_HI;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xA0;
                    sptwb.Spt.Cdb[9] = SMART_CMD;                      //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false || dwReturned != length)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, sata_smart_data_ptr, Marshal.SizeOf(typeof(DEVICE_ATTR_DATA)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }
            #endregion
        }

        private class SAT_SATA_Bridge : ExternBase
        {
            #region SAT 標準 SCSI Pass-Through Command
            public static bool DoIdentifyDevice(string filename, IntPtr sata_identufy_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (sata_identufy_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT));
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = IDENTIFY_BUFFER_SIZE;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 0x08;                //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0x0E;                //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = 0;                   //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 1;                   //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 0;                   //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = 0;                   //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = 0;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xA0;
                    sptwb.Spt.Cdb[9] = ID_CMD;     //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, (uint)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)), inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false || dwReturned != length)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, sata_identufy_data_ptr, Marshal.SizeOf(typeof(IDSECTOR)));
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                        hIoCtrl = null;
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool GetSmartAttribute(string filename, IntPtr sata_smart_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (sata_smart_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = READ_ATTRIBUTE_BUFFER_SIZE;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;                                    //ATA PASS THROUGH(12) OPERATION CODE(A1h)
                    sptwb.Spt.Cdb[1] = 0x08;                                    //MULTIPLE_COUNT=0,PROTOCOL=4(PIO Data-In),Reserved
                    sptwb.Spt.Cdb[2] = 0x0E;                                    //OFF_LINE=0,CK_COND=0,Reserved=0,T_DIR=1(ToDevice),BYTE_BLOCK=1,T_LENGTH=2
                    sptwb.Spt.Cdb[3] = READ_ATTRIBUTES;                //FEATURES (7:0)
                    sptwb.Spt.Cdb[4] = 1;                                       //SECTOR_COUNT (7:0)
                    sptwb.Spt.Cdb[5] = 1;                                       //LBA_LOW (7:0)
                    sptwb.Spt.Cdb[6] = SMART_CYL_LOW;                  //LBA_MID (7:0)
                    sptwb.Spt.Cdb[7] = SMART_CYL_HI;                   //LBA_HIGH (7:0)
                    sptwb.Spt.Cdb[8] = 0xA0;
                    sptwb.Spt.Cdb[9] = SMART_CMD;                      //COMMAND
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false || dwReturned != length)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, sata_smart_data_ptr, Marshal.SizeOf(typeof(DEVICE_ATTR_DATA)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }
            #endregion
        }

        #endregion
    }

    /// <summary>
    /// NVMe 對外界面。
    /// </summary>
    public class NVMe_Access : ExternBase
    {
        #region 單例處理
        //定義一個靜態變數來保存類的實體
        private static volatile NVMe_Access _instance;

        //定義一個標識確保執行緒同步
        private static readonly object locker = new object();

        //定義私有建構式，使外界不能創建該類實體，
        private NVMe_Access()
        {
            //Console.WriteLine("Singleton物件已被創建，");
        }

        /// <summary>
        /// 定義公有屬性來提供全域訪問點，
        /// </summary>
        public static NVMe_Access Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (locker)
                    {
                        // 如果類的實體不存在則創建，否則直接回傳
                        if (_instance == null)
                        {
                            _instance = new NVMe_Access();
                        }
                    }
                }
                return _instance;
            }
        }
        #endregion

        /// <summary>
        /// NVMe Get Identify Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 NVMe Identify 結構體存放指標</param>
        public bool NVMe_Identify_ReadData(int physicalDriveId, IntPtr pbuffer, int retryCount = 2)
        {
            string devFileName = GET_DEVICE_INFO.AP_Instance[physicalDriveId].pDevicePath;
            if (GET_DEVICE_INFO.AP_Instance[(int)physicalDriveId].ucNVMePathThrough == 1)
            {
                int index = DeviceAccess.Get_SCSI_Address(devFileName);
                if (index >= 0)
                {
                    devFileName = "\\\\.\\SCSI" + index + ":";
                    //Track.WriteLine(devFileName);
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
            //string aPath = "\\\\.\\SCSI1:";
            NVMe_Cmd cmd = NVMe_Cmd.Instance;
            bool ret = false;
            for (int i = 0; i < retryCount; i++)
            {
                // retry
                ret = cmd.Identify_ReadData_Cmd(devFileName, pbuffer);
                if (ret)
                {
                    break;
                }
                else
                {
                    Thread.Sleep(TimeSpan.FromSeconds(1));
                }
            }
            return ret;
        }

        /// <summary>
        /// NVMe Get Size。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="totalSize">外部傳入 Size 存放指標</param>
        public bool NVMe_Identify_NameSpace_ReadData(int physicalDriveId, ref UInt64 totalSize, int retryCount = 2)
        {
            string devFileName = GET_DEVICE_INFO.AP_Instance[physicalDriveId].pDevicePath;
            NVMe_Cmd cmd = NVMe_Cmd.Instance;
            bool ret = false;
            for (int i = 0; i < retryCount; i++)
            {
                // retry
                ret = cmd.Identify_NameSpace_ReadData_Cmd(devFileName, ref totalSize);
                if (ret)
                {
                    break;
                }
                else
                {
                    Thread.Sleep(TimeSpan.FromSeconds(1));
                }
            }
            return ret;
        }

        /// <summary>
        /// NVMe Get SMART Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 NVMe SMART 結構體存放指標</param>
        public bool NVMe_SMART_ReadData(int physicalDriveId, IntPtr pbuffer, int retryCount = 2, COMMAND_TYPE aCOMMAND_TYPE = COMMAND_TYPE.CMD_TYPE_UNKNOWN)
        {
            string devFileName = GET_DEVICE_INFO.AP_Instance[physicalDriveId].pDevicePath;
            if (GET_DEVICE_INFO.AP_Instance[(int)physicalDriveId].ucNVMePathThrough == 1)
            {
                int index = DeviceAccess.Get_SCSI_Address(devFileName);
                if (index >= 0)
                {
                    devFileName = "\\\\.\\SCSI" + index + ":";
                    Track.WriteLine(devFileName);
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
            //string aPath = "\\\\.\\SCSI1:";
            NVMe_Cmd cmd = NVMe_Cmd.Instance;
            bool ret = false;
            for (int i = 0; i < retryCount; i++)
            {
                // retry
                ret = cmd.SMART_ReadData_Cmd(devFileName, pbuffer, aCOMMAND_TYPE);
                if (ret)
                {
                    break;
                }
                else
                {
                    Thread.Sleep(TimeSpan.FromSeconds(1));
                }
            }
            return ret;
        }

        /// <summary>
        /// NVMe Get SMART Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 NVMe SMART 結構體存放指標</param>
        public bool NVMe_Format(int physicalDriveId, int retryCount = 2, COMMAND_TYPE aCOMMAND_TYPE = COMMAND_TYPE.CMD_TYPE_UNKNOWN)
        {
            string devFileName = GET_DEVICE_INFO.AP_Instance[physicalDriveId].pDevicePath;
            if (GET_DEVICE_INFO.AP_Instance[(int)physicalDriveId].ucNVMePathThrough == 1)
            {
                int index = DeviceAccess.Get_SCSI_Address(devFileName);
                if (index >= 0)
                {
                    devFileName = "\\\\.\\SCSI" + index + ":";
                    Track.WriteLine(devFileName);
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
            //string aPath = "\\\\.\\SCSI1:";
            NVMe_Cmd cmd = NVMe_Cmd.Instance;
            bool ret = false;
            for (int i = 0; i < retryCount; i++)
            {
                // retry
                ret = cmd.NVMe_Format_Cmd(devFileName, aCOMMAND_TYPE);
                if (ret)
                {
                    break;
                }
                else
                {
                    Thread.Sleep(TimeSpan.FromSeconds(1));
                }
            }
            return ret;
        }

        /// <summary>
        /// NVMe DeviceSelfTest。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="_iAction">1h: start short test, 2h: start extended test, Fh: abort test</param>
        public bool NVMe_DeviceSelfTest(int physicalDriveId, int _iAction)
        {
            string devFileName = GET_DEVICE_INFO.AP_Instance[physicalDriveId].pDevicePath;
            if (GET_DEVICE_INFO.AP_Instance[(int)physicalDriveId].ucNVMePathThrough == 1)
            {
                int index = DeviceAccess.Get_SCSI_Address(devFileName);
                if (index >= 0)
                {
                    devFileName = "\\\\.\\SCSI" + index + ":";
                    Track.WriteLine(devFileName);
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            return NVMe_Cmd.Instance.DeviceSelfTest_Cmd(devFileName, _iAction);
        }

        /// <summary>
        /// NVMe Get DeviceSelfTestLog Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 NVMe DeviceSelfTestLog 結構體存放指標</param>
        public bool NVMe_GetDeviceSelfTestLog(int physicalDriveId, IntPtr pbuffer)
        {
            string devFileName = GET_DEVICE_INFO.AP_Instance[physicalDriveId].pDevicePath;
            if (GET_DEVICE_INFO.AP_Instance[(int)physicalDriveId].ucNVMePathThrough == 1)
            {
                int index = DeviceAccess.Get_SCSI_Address(devFileName);
                if (index >= 0)
                {
                    devFileName = "\\\\.\\SCSI" + index + ":";
                    Track.WriteLine(devFileName);
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }

            return NVMe_Cmd.Instance.GetDeviceSelfTestLog_Cmd(devFileName, pbuffer);
        }

        /// <summary>
        /// NVMe USB Get Identify Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 SATA Identify 結構體存放指標</param>
        /// <param name="ModelControl">傳入 SCSIVendor 字串，可為空字串。</param>
        /// <param name="USB_VendorID">USB VID</param>
        /// <param name="USB_ProductID">USB PID</param>
        public bool NVMe_USB_Identify_ReadData(int physicalDriveId, IntPtr pbuffer, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            COMMAND_TYPE aCommandType = GetModelControl(ModelControl, USB_VendorID, USB_ProductID);
            NVMe_Cmd cmd = NVMe_Cmd.Instance;

            if (aCommandType != COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                switch (aCommandType)
                {
                    case COMMAND_TYPE.CMD_TYPE_NVME_JMICRON:
                        {
                            // DiskPart_API.Disk_Rescan(); //  JMS583 Bridge 轉板，有BUG。放一段時間會進入休眠，會造成 SCSI Command 打不下去。
                            return cmd.NVMe_USB_Identify_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_REALTEK:
                        {
                            return cmd.NVMe_USB_Identify_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA:
                        {
                            return cmd.NVMe_USB_Identify_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    default:
                        {
                            return false;
                        }
                        break;
                }
            }
            else
            {
                Track.WriteLine("NVMe_USB_Identify_ReadData 不支援的 Control Model = {0}", ModelControl);
                return false;
            }
        }

        /// <summary>
        /// NVMe USB Get NameSpace Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 NVMe NameSpace 結構體存放指標</param>
        /// <param name="ModelControl">傳入 SCSIVendor 字串，可為空字串。</param>
        /// <param name="USB_VendorID">USB VID</param>
        /// <param name="USB_ProductID">USB PID</param>
        public bool NVMe_USB_Identify_NameSpace_ReadData(int physicalDriveId, IntPtr pbuffer, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            COMMAND_TYPE aCommandType = GetModelControl(ModelControl, USB_VendorID, USB_ProductID);
            NVMe_Cmd cmd = NVMe_Cmd.Instance;

            if (aCommandType != COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                switch (aCommandType)
                {
                    case COMMAND_TYPE.CMD_TYPE_NVME_JMICRON:
                        {
                            return cmd.NVMe_USB_Identify_NameSpace_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_REALTEK:
                        {
                            return cmd.NVMe_USB_Identify_NameSpace_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA:
                        {
                            return cmd.NVMe_USB_Identify_NameSpace_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    default:
                        {
                            return false;
                        }
                        break;
                }
            }
            else
            {
                Track.WriteLine("NVMe_USB_Identify_NameSpace_ReadData 不支援的 Control Model = {0}", ModelControl);
                return false;
            }
        }

        /// <summary>
        /// NVMe USB Get Size
        /// 註: 因為 CDI中，絕大多數 USB to NVMe，都是透過 WMI 得知容量的寫法。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="totalSize">外部傳入 Size 指標</param>
        public bool NVMe_USB_Identify_NameSpace_ReadData(int physicalDriveId, ref UInt64 totalSize)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            NVMe_Cmd cmd = NVMe_Cmd.Instance;
            return cmd.NVMe_USB_Identify_NameSpace_ReadData_Cmd(devFileName, ref totalSize);
        }

        /// <summary>
        /// NVMe USB Get SMART Data。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="pbuffer">外部傳入 NVMe SMART 結構體存放指標</param>
        /// <param name="ModelControl">傳入 SCSIVendor 字串，可為空字串。</param>
        /// <param name="USB_VendorID">USB VID</param>
        /// <param name="USB_ProductID">USB PID</param>
        public bool NVMe_USB_SMART_ReadData(int physicalDriveId, IntPtr pbuffer, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            COMMAND_TYPE aCommandType = GetModelControl(ModelControl, USB_VendorID, USB_ProductID);
            NVMe_Cmd cmd = NVMe_Cmd.Instance;

            if (aCommandType != COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                switch (aCommandType)
                {
                    case COMMAND_TYPE.CMD_TYPE_NVME_JMICRON:
                        {
                            // DiskPart_API.Disk_Rescan(); //  JMS583 Bridge 轉板，有BUG。放一段時間會進入休眠，會造成 SCSI Command 打不下去。
                            return cmd.NVMe_USB_GetSmartAttribute_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_REALTEK:
                        {
                            return cmd.NVMe_USB_GetSmartAttribute_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA:
                        {
                            return cmd.NVMe_USB_GetSmartAttribute_ReadData_Cmd(devFileName, pbuffer, aCommandType);
                        }
                        break;
                    default:
                        {
                            return false;
                        }
                        break;
                }
            }
            else
            {
                Track.WriteLine("NVMe_USB_SMART_ReadData 不支援的 Control Model = {0}", ModelControl);
                return false;
            }
        }

        /// <summary>
        /// NVMe USB Format。
        /// 註: CDW10 => '0', 未請求安全擦除，由控制器廠商自行決定。
        /// 註: CDW10 => '0x200', 請求安全擦除，但是詳細(清表單 / 寫 0 / 寫 1 / Block Erase) 由控制器廠商自行決定。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="ModelControl">傳入 SCSIVendor 字串，可為空字串。</param>
        /// <param name="USB_VendorID">USB VID</param>
        /// <param name="USB_ProductID">USB PID</param>
        public bool NVMe_USB_Format(int physicalDriveId, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            COMMAND_TYPE aCommandType = GetModelControl(ModelControl, USB_VendorID, USB_ProductID);
            NVMe_Cmd cmd = NVMe_Cmd.Instance;

            if (aCommandType != COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                switch (aCommandType)
                {
                    case COMMAND_TYPE.CMD_TYPE_NVME_JMICRON:
                        {
                            // DiskPart_API.Disk_Rescan(); //  JMS583 Bridge 轉板，有BUG。放一段時間會進入休眠，會造成 SCSI Command 打不下去。
                            return cmd.NVMe_USB_Format_Cmd(devFileName, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_REALTEK:
                        {
                            return cmd.NVMe_USB_Format_Cmd(devFileName, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA:
                        {
                            return cmd.NVMe_USB_Format_Cmd(devFileName, aCommandType);
                        }
                        break;
                    default:
                        {
                            return false;
                        }
                        break;
                }
            }
            else
            {
                Track.WriteLine("NVMe_USB_Format 不支援的 Control Model = {0}", ModelControl);
                return false;
            }
        }

        /// <summary>
        /// NVMe USB Sanitize。
        ///  註: CDW10 => '1', 強制離開。
        ///  註: CDW10 => '2', 強制 Block Erase。
        ///  註: CDW10 => '3'，強制覆寫 Data，內容看"CDW11"，廠商不一定有實作。
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="ModelControl">傳入 SCSIVendor 字串，可為空字串。</param>
        /// <param name="USB_VendorID">USB VID</param>
        /// <param name="USB_ProductID">USB PID</param>
        public bool NVMe_USB_Sanitize(int physicalDriveId, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            COMMAND_TYPE aCommandType = GetModelControl(ModelControl, USB_VendorID, USB_ProductID);
            NVMe_Cmd cmd = NVMe_Cmd.Instance;

            if (aCommandType != COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                switch (aCommandType)
                {
                    case COMMAND_TYPE.CMD_TYPE_NVME_JMICRON:
                        {
                            // DiskPart_API.Disk_Rescan(); //  JMS583 Bridge 轉板，有BUG。放一段時間會進入休眠，會造成 SCSI Command 打不下去。
                            return cmd.NVMe_USB_Sanitize_Cmd(devFileName, aCommandType);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_REALTEK:
                        {
                            return false;
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA:
                        {
                            return cmd.NVMe_USB_Sanitize_Cmd(devFileName, aCommandType);
                        }
                        break;
                    default:
                        {
                            return false;
                        }
                        break;
                }
            }
            else
            {
                Track.WriteLine("NVMe_USB_Format 不支援的 Control Model = {0}", ModelControl);
                return false;
            }
        }

        /// <summary>
        /// USB to NVMe 轉板透過，設定 電源狀態。
        /// 註: JMS583 轉板。 aStatus = 0 => PS0 + L0 / aStatus = 1 => PS3 + L1.2
        /// 註: ASM2362 轉板。 aStatus = 0 => PS0 + L0 / aStatus = 1 => PS0 + L1.2 / aStatus = 3 => PS3 + L1.2 / / aStatus = 4 => PS4 + L1.2
        /// </summary>
        /// <param name="physicalDriveId">磁碟 Index</param>
        /// <param name="ModelControl">傳入 SCSIVendor 字串，可為空字串。</param>
        /// <param name="USB_VendorID">USB VID</param>
        /// <param name="USB_ProductID">USB PID</param>
        /// <param name="aStatus">設定電源狀態</param>
        public bool NVMe_USB_Power(int physicalDriveId, string ModelControl, string USB_VendorID, string USB_ProductID, uint aStatus = 0)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);
            COMMAND_TYPE aCommandType = GetModelControl(ModelControl, USB_VendorID, USB_ProductID);
            NVMe_Cmd cmd = NVMe_Cmd.Instance;

            if (aCommandType != COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                switch (aCommandType)
                {
                    case COMMAND_TYPE.CMD_TYPE_NVME_JMICRON:
                        {
                            // DiskPart_API.Disk_Rescan(); //  JMS583 Bridge 轉板，有BUG。放一段時間會進入休眠，會造成 SCSI Command 打不下去。
                            return cmd.NVMe_USB_DigitalWattmeter_Cmd(devFileName, aCommandType, aStatus);
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_REALTEK:
                        {
                            Track.WriteLine(@"NVMe_USB_Power REALTEK 設備不支援");
                            return false;
                        }
                        break;
                    case COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA:
                        {
                            return cmd.NVMe_USB_DigitalWattmeter_Cmd(devFileName, aCommandType, aStatus);
                        }
                        break;
                    default:
                        {
                            return false;
                        }
                        break;
                }
            }
            else
            {
                Track.WriteLine("NVMe_USB_Power 不支援的 Control Model = {0}", ModelControl);
                return false;
            }
        }

        public bool NVMe_ReadWrite_LBA(int physicalDriveId, UInt64 startLBA, byte[] data, int len, bool _IsWrite)
        {
            string devFileName = GetPhysicalDriveNamePath(physicalDriveId);

            return NVMe_Cmd.Instance.LBA_ReadWrite_Cmd(devFileName, startLBA, data, len, _IsWrite);
        }

        #region 工具區
        /// <summary> 
        /// 判讀 USB 的 Model 是哪一家的。 
        /// 目前不確定這寫法的萬用性，只是根據撈到的 "WMI Model" 資訊，進行判別分類。  
        /// </summary> 
        private COMMAND_TYPE GetModelControl(string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            COMMAND_TYPE aCommandType = COMMAND_TYPE.CMD_TYPE_UNKNOWN;
            string tempModelControl = ModelControl.ToLower();

            if (tempModelControl.Contains(@"JMicron".ToLower()))
            {
                // JMicron USB Model 
                aCommandType = COMMAND_TYPE.CMD_TYPE_NVME_JMICRON;
            }

            // 發生透過 ModelControl 資訊，無法識別廠商，進一步透過 USB VID判斷。 
            if (aCommandType == COMMAND_TYPE.CMD_TYPE_UNKNOWN)
            {
                // 進一步透過，USB VID判斷 
                try
                {
                    int tempUSB_VendorID = Int32.Parse(USB_VendorID, System.Globalization.NumberStyles.HexNumber);
                    int tempUSB_ProductID = Int32.Parse(USB_ProductID, System.Globalization.NumberStyles.HexNumber);

                    if (tempUSB_VendorID == (int)VENDOR_ID.USB_VENDOR_REALTEK)
                    {
                        // USB Realtek 
                        aCommandType = COMMAND_TYPE.CMD_TYPE_NVME_REALTEK;
                    }
                    else if (tempUSB_VendorID == (int)VENDOR_ID.USB_VENDOR_JMICRON)
                    {
                        // JMicron USB Model 
                        aCommandType = COMMAND_TYPE.CMD_TYPE_NVME_JMICRON;
                    }
                    else if (tempUSB_VendorID == (int)VENDOR_ID.USB_VENDOR_ASMEDIA)
                    {
                        // ASMedia USB Model 
                        aCommandType = COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA;
                    }
                    else
                    {
                        // 1. 因為 ADATA VID 底下，有各家用的USB裝置，因此無法當作依據判斷哪種命令。
                        // 2. 因為 ADATA 會幫廠商客製 USB外接裝置，因此VID 有機會被改成客製商的VID，因此也不準。
                        // 結論: 這類型都透過 MES資訊上 和 Default XML檔紀錄的，Bridge Control Name，去映射。
                        return BridgeControlName_MappingCommands.GetCommandType();
                    }
                }
                catch (Exception)
                {

                    aCommandType = COMMAND_TYPE.CMD_TYPE_UNKNOWN;
                }

            }

            return aCommandType;
        }

        /// <summary>
        /// 判讀 USB 的 裝置硬碟 是否為 NVMe 設備。
        /// </summary>
        public bool NVMe_USB_Device_Check(int physicalDriveId, string ModelControl, string USB_VendorID, string USB_ProductID)
        {
            bool isNVMe = false;

            IntPtr identify_data = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));

            try
            {
                isNVMe = NVMe_USB_Identify_ReadData(physicalDriveId, identify_data, ModelControl, USB_VendorID, USB_ProductID);
            }
            catch (Exception ex)
            {
                Track.WriteLine(ex.ToString());
                isNVMe = false;
            }
            finally
            {
                if (identify_data != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(identify_data);
                    identify_data = IntPtr.Zero;
                }
            }
            return isNVMe;
        }


        #endregion
    }

    /// <summary>
    /// NVMe 內部實作。
    /// </summary>
    public class NVMe_Cmd : ExternBase
    {
        #region 單例處理
        //定義一個靜態變數來保存類的實體
        private static volatile NVMe_Cmd _instance;

        //定義一個標識確保執行緒同步
        private static readonly object locker = new object();

        //定義私有建構式，使外界不能創建該類實體，
        private NVMe_Cmd()
        {
            //Console.WriteLine("Singleton物件已被創建，");
        }

        /// <summary>
        /// 定義公有屬性來提供全域訪問點，
        /// </summary>
        public static NVMe_Cmd Instance
        {
            get
            {
                if (_instance == null)
                {
                    lock (locker)
                    {
                        // 如果類的實體不存在則創建，否則直接回傳
                        if (_instance == null)
                        {
                            _instance = new NVMe_Cmd();
                        }
                    }
                }
                return _instance;
            }
        }
        #endregion

        #region NVMe 板載 對外相關
        public bool Identify_ReadData_Cmd(string filename, IntPtr identify_data)
        {
            bool nRet = false;
            IntPtr aIdentify_data = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));
            // 下面的方法，雖然執行上有點多餘，但是還是最好先確保，COMMAND 種類，確認邏輯上分類的連貫性。

            try
            {
                if (IntelNVMeOnboard.DoIdentifyDevice(filename, aIdentify_data))
                {
                    // 代表屬於 intel 陣營的識別方法
                    return GetIdentify(filename, identify_data, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);
                }

                if (StorageNVMeOnboard.DoIdentifyDevice(filename, aIdentify_data))
                {
                    // 代表屬於 微軟標準 陣營的識別方法
                    return GetIdentify(filename, identify_data, COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY);
                }
            }
            catch (Exception ex)
            {
                Track.WriteLine(ex.ToString());
            }
            finally
            {
                Marshal.FreeHGlobal(aIdentify_data);
                aIdentify_data = IntPtr.Zero;
            }

            return nRet;
        }

        public bool Identify_NameSpace_ReadData_Cmd(string filename, ref UInt64 totalSize)
        {
            return StorageNVMeOnboard.DoIdentifyNameSpaceDevice(filename, ref totalSize);
        }

        public bool SMART_ReadData_Cmd(string filename, IntPtr smart_data, COMMAND_TYPE aCOMMAND_TYPE = COMMAND_TYPE.CMD_TYPE_UNKNOWN)
        {
            bool nRet = false;
            IntPtr identify_data = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));

            try
            {
                if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_UNKNOWN)
                {
                    if (IntelNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                    {
                        // 代表屬於 intel 陣營的識別方法
                        return GetSmartAttribute(filename, smart_data, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);

                    }

                    if (StorageNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                    {
                        // 代表屬於 微軟標準 陣營的識別方法
                        return GetSmartAttribute(filename, smart_data, COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY);
                    }
                }
                else if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
                {
                    return GetSmartAttribute(filename, smart_data, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);
                }
                else if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
                {
                    return GetSmartAttribute(filename, smart_data, COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY);
                }
            }
            catch (Exception ex)
            {
                Track.WriteLine(ex.ToString());
            }
            finally
            {
                Marshal.FreeHGlobal(identify_data);
                identify_data = IntPtr.Zero;
            }
            return nRet;
        }

        public bool NVMe_Format_Cmd(string filename, COMMAND_TYPE aCOMMAND_TYPE = COMMAND_TYPE.CMD_TYPE_UNKNOWN)
        {
            bool nRet = false;
            IntPtr identify_data = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));

            try
            {
                if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_UNKNOWN)
                {
                    if (IntelNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                    {
                        // 代表屬於 intel 陣營的識別方法
                        return ExecuteNVMe_Format_Cmd(filename, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);
                    }

                    if (StorageNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                    {
                        // 代表屬於 微軟標準 陣營的識別方法
                        //  目前不支援，微軟標準驅動下的 Format。
                        Track.WriteLine(@"NVMe_Format_Cmd - 目前不支援微軟標準驅動。");
                    }
                }
                else if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
                {
                    return ExecuteNVMe_Format_Cmd(filename, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);
                }
                else if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
                {
                    Track.WriteLine(@"NVMe_Format_Cmd - 目前不支援微軟標準驅動。");
                }
            }
            catch (Exception ex)
            {
                Track.WriteLine(ex.ToString());
            }
            finally
            {
                Marshal.FreeHGlobal(identify_data);
                identify_data = IntPtr.Zero;
            }
            return nRet;
        }

        public bool DeviceSelfTest_Cmd(string filename, int _Action, COMMAND_TYPE aCOMMAND_TYPE = COMMAND_TYPE.CMD_TYPE_UNKNOWN)
        {
            bool nRet = false;
            IntPtr identify_data = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));

            try
            {
                if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_UNKNOWN)
                {
                    if (IntelNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                    {
                        // 代表屬於 intel 陣營的識別方法
                        nRet = SetDeviceSelfTest(filename, _Action, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);
                    }

                    if (StorageNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                    {
                        // 代表屬於 微軟標準 陣營的識別方法
                        nRet = SetDeviceSelfTest(filename, _Action, COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY);
                    }
                }
                else if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
                {
                    nRet = SetDeviceSelfTest(filename, _Action, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);
                }
                else if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
                {
                    nRet = SetDeviceSelfTest(filename, _Action, COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY);
                }
            }
            catch (Exception ex)
            {
                Track.WriteLine(ex.ToString());
            }
            finally
            {
                Marshal.FreeHGlobal(identify_data);
                identify_data = IntPtr.Zero;
            }

            return nRet;
        }

        public bool GetDeviceSelfTestLog_Cmd(string filename, IntPtr _DeviceSelfTes_Data, COMMAND_TYPE aCOMMAND_TYPE = COMMAND_TYPE.CMD_TYPE_UNKNOWN)
        {
            bool nRet = false;
            IntPtr identify_data = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));

            try
            {
                if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_UNKNOWN)
                {
                    if (IntelNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                    {
                        // 代表屬於 intel 陣營的識別方法
                        nRet = GetDeviceSelfTestLog(filename, _DeviceSelfTes_Data, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);
                    }

                    if (StorageNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                    {
                        // 代表屬於 微軟標準 陣營的識別方法
                        nRet = GetDeviceSelfTestLog(filename, _DeviceSelfTes_Data, COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY);
                    }
                }
                else if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
                {
                    nRet = GetDeviceSelfTestLog(filename, _DeviceSelfTes_Data, COMMAND_TYPE.CMD_TYPE_NVME_INTEL);
                }
                else if (aCOMMAND_TYPE == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
                {
                    nRet = GetDeviceSelfTestLog(filename, _DeviceSelfTes_Data, COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY);
                }
            }
            catch (Exception ex)
            {
                Track.WriteLine(ex.ToString());
            }
            finally
            {
                Marshal.FreeHGlobal(identify_data);
                identify_data = IntPtr.Zero;
            }

            return nRet;
        }

        /// <summary>
        /// ReadWrite_LBA。
        /// </summary>
        /// <param name="filename">Ex: "\\\\.\\PHYSICALDRIVE2"。 注意不可用 "\\\\.\\SCSI1:"</param>
        /// <param name="startLBA">起始 LBA 地址</param>
        /// <param name="data">Buffer區塊 ，請勿超過 4096 Bytes。</param>
        /// <param name="len">要傳輸的 LBA 長度</param>
        /// <param name="_IsWrite">是否 Write 動作</param>
        public bool LBA_ReadWrite_Cmd(string filename, UInt64 startLBA, byte[] data, int len, bool _IsWrite)
        {
            if (_IsWrite)
            {
                return SCSI_IO.Write_LBA(filename, startLBA, data, len);
            }
            else
            {
                return SCSI_IO.Read_LBA(filename, startLBA, data, len);
            }
        }

        private bool SetDeviceSelfTest(string filename, int _Action, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
            {
                if (StorageNVMeOnboard.DeviceSelfTest(filename, _Action))
                {
                    // 成功
                    nRet = true;
                }
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
            {
                if (IntelNVMeOnboard.DeviceSelfTest(filename, _Action))
                {
                    // 成功
                    nRet = true;
                }
            }

            return nRet;
        }

        private bool GetIdentify(string filename, IntPtr identify_data, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
            {
                if (IntelNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                {
                    //Console.WriteLine("代表讀取 Realtek NVMe Identify DATA 成功");
                    nRet = true;
                }
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
            {
                if (StorageNVMeOnboard.DoIdentifyDevice(filename, identify_data))
                {
                    //Console.WriteLine("代表讀取 微軟 NVMe Identify DATA 成功");
                    nRet = true;
                }
            }


            return nRet;
        }

        private bool GetSmartAttribute(string filename, IntPtr smartData, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
            {
                if (IntelNVMeOnboard.GetSmartAttribute(filename, smartData))
                {
                    //Console.WriteLine("代表讀取 Realtek NVMe SMART DATA 成功");
                    nRet = true;
                }
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
            {
                if (StorageNVMeOnboard.GetSmartAttribute(filename, smartData))
                {
                    //Console.WriteLine("代表讀取 Realtek NVMe SMART DATA 成功");
                    nRet = true;
                }
            }


            return nRet;
        }

        private bool ExecuteNVMe_Format_Cmd(string filename, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
            {
                nRet = IntelNVMeOnboard.FormatDevice(filename);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
            {
                //  目前不支援
            }

            return nRet;
        }

        private bool GetDeviceSelfTestLog(string filename, IntPtr _DeviceSelfTes_Data, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_STORAGE_QUERY)
            {
                if (StorageNVMeOnboard.GetDeviceSelfTestLog(filename, _DeviceSelfTes_Data))
                {
                    //Console.WriteLine("代表讀取 微軟 SelfTestLog DATA 成功");
                    nRet = true;
                }
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_INTEL)
            {
                if (IntelNVMeOnboard.GetDeviceSelfTestLog(filename, _DeviceSelfTes_Data))
                {
                    //Console.WriteLine("代表讀取 Intel SelfTestLog DATA 成功");
                    nRet = true;
                }
            }

            return nRet;
        }
        #endregion

        #region NVMe USB Bridge 對外相關
        /// <summary>
        /// 讀取 Identify 資訊(USB to NVMe)
        /// </summary>
        internal bool NVMe_USB_Identify_ReadData_Cmd(string filename, IntPtr identify_data, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_JMICRON)
            {
                // USB Bridge Jmicron
                return JMicronNVMeBridge.DoIdentifyDevice(filename, identify_data);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_REALTEK)
            {
                // USB Bridge Realtek
                return RealtekNVMeBridge.DoIdentifyDevice(filename, identify_data);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA)
            {
                // USB Bridge ASMedia
                return ASMediaNVMeBridge.DoIdentifyDevice(filename, identify_data);
            }

            return nRet;
        }

        /// <summary>
        /// 讀取 NameSpace 資訊(USB to NVMe)
        /// </summary>
        internal bool NVMe_USB_Identify_NameSpace_ReadData_Cmd(string filename, IntPtr nvme_identufy_namespace_data_ptr, COMMAND_TYPE commandType)
        {
            bool nRet = false;

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_JMICRON)
            {
                // USB Bridge Jmicron
                return JMicronNVMeBridge.DoIdentifyNameSpaceDevice(filename, nvme_identufy_namespace_data_ptr);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_REALTEK)
            {
                // USB Bridge Realtek
                return RealtekNVMeBridge.DoIdentifyNameSpaceDevice(filename, nvme_identufy_namespace_data_ptr);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA)
            {
                // USB Bridge ASMedia
                return ASMediaNVMeBridge.DoIdentifyNameSpaceDevice(filename, nvme_identufy_namespace_data_ptr);
            }

            return nRet;
        }

        /// <summary>
        /// 直接讀取 容量大小 資訊(USB to NVMe)
        /// 註: 因為多數 CDI USB Bridge 型號，並沒實作讀取NameSpace的方法。都是透過 WMI 直接拿取容量。
        /// </summary>
        internal bool NVMe_USB_Identify_NameSpace_ReadData_Cmd(string filename, ref UInt64 totalSize)
        {
            // 因為是透過 WMI拿取，就沒分型號識別。
            return StorageNVMeOnboard.DoIdentifyNameSpaceDevice(filename, ref totalSize);
        }

        /// <summary>
        /// 讀取 SMART 資訊(USB to NVMe)
        /// </summary>
        internal bool NVMe_USB_GetSmartAttribute_ReadData_Cmd(string filename, IntPtr smart_data, COMMAND_TYPE commandType)
        {
            bool nRet = false;
            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_JMICRON)
            {
                // USB Bridge Jmicron
                return JMicronNVMeBridge.GetSmartAttribute(filename, smart_data);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_REALTEK)
            {
                // USB Bridge Realtek
                return RealtekNVMeBridge.GetSmartAttribute(filename, smart_data);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA)
            {
                // USB Bridge ASMedia
                return ASMediaNVMeBridge.GetSmartAttribute(filename, smart_data);
            }
            return nRet;
        }

        /// <summary>
        /// Secure Erase(USB to NVMe)
        /// </summary>
        internal bool NVMe_USB_Format_Cmd(string filename, COMMAND_TYPE commandType)
        {
            bool nRet = false;
            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_JMICRON)
            {
                // USB Bridge Jmicron
                nRet = JMicronNVMeBridge.FormatDevice(filename);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_REALTEK)
            {
                // USB Bridge Realtek
                nRet = RealtekNVMeBridge.FormatDevice(filename);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA)
            {
                // USB Bridge ASMedia
                nRet = ASMediaNVMeBridge.FormatDevice(filename);
            }

            return nRet;
        }

        /// <summary>
        /// Secure(Sanitize) Erase (USB to NVMe)
        /// </summary>
        internal bool NVMe_USB_Sanitize_Cmd(string filename, COMMAND_TYPE commandType)
        {
            bool nRet = false;
            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_JMICRON)
            {
                // USB Bridge Jmicron
                nRet = JMicronNVMeBridge.SanitizeDevice(filename);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_REALTEK)
            {
                // USB Bridge Realtek

            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA)
            {
                // USB Bridge ASMedia
                nRet = ASMediaNVMeBridge.SanitizeDevice(filename);
            }

            return nRet;
        }

        /// <summary>
        /// 電源狀態設定 (USB to NVMe)
        /// </summary>
        internal bool NVMe_USB_DigitalWattmeter_Cmd(string filename, COMMAND_TYPE commandType, uint aStatus)
        {
            bool nRet = false;
            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_JMICRON)
            {
                // USB Bridge Jmicron
                nRet = JMicronNVMeBridge.Set_Bridge_Power(filename, aStatus);
            }

            if (commandType == COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA)
            {
                // USB Bridge ASMEDIA
                nRet = ASMediaNVMeBridge.Set_Bridge_Power(filename, aStatus);
            }

            return nRet;
        }
        #endregion

        #region Onboard
        public class StorageNVMeOnboard : ExternBase
        {
            #region  NVMe Storage Query
            /*---------------------------------------------------------------------------*/
            // NVMe Storage Query
            // Reference: http://naraeon.net/en/archives/1338
            /*---------------------------------------------------------------------------*/
            public static bool DoIdentifyDevice(string filename, IntPtr data)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TStorageQueryWithBuffer)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    TStorageQueryWithBuffer nptwb = new TStorageQueryWithBuffer();

                    nptwb.ProtocolSpecific.ProtocolType = TStroageProtocolType.ProtocolTypeNvme;
                    nptwb.ProtocolSpecific.DataType = (Int32)TStorageProtocolNVMeDataType.NVMeDataTypeIdentify;
                    nptwb.ProtocolSpecific.ProtocolDataOffset = Marshal.SizeOf(typeof(TStorageProtocolSpecificData));
                    nptwb.ProtocolSpecific.ProtocolDataLength = 4096;
                    nptwb.ProtocolSpecific.ProtocolDataRequestValue = 1; /*NVME_IDENTIFY_CNS_CONTROLLER*/
                    nptwb.ProtocolSpecific.ProtocolDataRequestSubValue = 0;
                    nptwb.Query.PropertyId = TStoragePropertyId.StorageAdapterProtocolSpecificProperty;
                    nptwb.Query.QueryType = TStorageQueryType.PropertyStandardQuery;
                    nptwb.Buffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IOCTL_STORAGE_QUERY_PROPERTY, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    nptwb = (TStorageQueryWithBuffer)Marshal.PtrToStructure(inpBuffer, typeof(TStorageQueryWithBuffer));

                    hIoCtrl.Close();
                    Marshal.Copy(nptwb.Buffer, 0, data, Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));
                    /*
                    NVME_IDENTIFY_DEVICE test = (NVME_IDENTIFY_DEVICE)Marshal.PtrToStructure(data, typeof(NVME_IDENTIFY_DEVICE));
                    string Model = new string(test.Model);
                    */
                    return nRet;
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
            }

            public static bool DoIdentifyNameSpaceDevice(string filename, IntPtr data)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TStorageQueryWithBuffer)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    TStorageQueryWithBuffer nptwb = new TStorageQueryWithBuffer();

                    nptwb.ProtocolSpecific.ProtocolType = TStroageProtocolType.ProtocolTypeNvme;
                    nptwb.ProtocolSpecific.DataType = (Int32)TStorageProtocolNVMeDataType.NVMeDataTypeIdentify;
                    nptwb.ProtocolSpecific.ProtocolDataOffset = Marshal.SizeOf(typeof(TStorageProtocolSpecificData));
                    nptwb.ProtocolSpecific.ProtocolDataLength = 4096;
                    nptwb.ProtocolSpecific.ProtocolDataRequestValue = 0; /*Identify Namespace data structure*/
                    nptwb.ProtocolSpecific.ProtocolDataRequestSubValue = 1;
                    nptwb.Query.PropertyId = TStoragePropertyId.StorageAdapterProtocolSpecificProperty;
                    nptwb.Query.QueryType = TStorageQueryType.PropertyStandardQuery;
                    nptwb.Buffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IOCTL_STORAGE_QUERY_PROPERTY, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    nptwb = (TStorageQueryWithBuffer)Marshal.PtrToStructure(inpBuffer, typeof(TStorageQueryWithBuffer));

                    hIoCtrl.Close();
                    Marshal.Copy(nptwb.Buffer, 0, data, Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));  //  namespace 最大size 與 NVME_IDENTIFY_DEVICE 結構體相同，因為目前 Namespace結構體，並未建立。
                    /*
                    NVME_IDENTIFY_DEVICE test = (NVME_IDENTIFY_DEVICE)Marshal.PtrToStructure(data, typeof(NVME_IDENTIFY_DEVICE));
                    string Model = new string(test.Model);
                    */
                    return nRet;
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
            }

            /// <summary>
            /// 拿取NVMe Storage Query 容量。
            /// 註: CDI 的寫法是 透過 系統 WMI　詢問容量
            /// filename => Ex: "\\\\.\\PHYSICALDRIVE2"
            /// </summary>
            public static bool DoIdentifyNameSpaceDevice(string filename, ref UInt64 totalSize)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = false;

                try
                {
                    string query = string.Format("select * from Win32_DiskDrive");
                    using (ManagementObjectSearcher m = new ManagementObjectSearcher(query))
                    {
                        foreach (ManagementObject o in m.Get())
                        {
                            if (((string)o["Name"]).ToLower() == filename.ToLower())
                            {
                                totalSize = (UInt64)o["Size"]; // 單位: Bytes
                                bRet = true;
                                break;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                }

                return bRet;
            }

            public static bool GetSmartAttribute(string filename, IntPtr data)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(TStorageQueryWithBuffer)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    TStorageQueryWithBuffer nptwb = new TStorageQueryWithBuffer();

                    nptwb.ProtocolSpecific.ProtocolType = TStroageProtocolType.ProtocolTypeNvme;
                    nptwb.ProtocolSpecific.DataType = (Int32)TStorageProtocolNVMeDataType.NVMeDataTypeLogPage;
                    nptwb.ProtocolSpecific.ProtocolDataOffset = Marshal.SizeOf(typeof(TStorageProtocolSpecificData));
                    nptwb.ProtocolSpecific.ProtocolDataLength = 4096;
                    nptwb.ProtocolSpecific.ProtocolDataRequestValue = 2; // SMART Health Information
                    nptwb.ProtocolSpecific.ProtocolDataRequestSubValue = 0;
                    nptwb.Query.PropertyId = TStoragePropertyId.StorageAdapterProtocolSpecificProperty;
                    nptwb.Query.QueryType = TStorageQueryType.PropertyStandardQuery;
                    nptwb.Buffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IOCTL_STORAGE_QUERY_PROPERTY, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);
                    if (nRet == false)
                    {
                        nptwb.ProtocolSpecific.ProtocolDataRequestSubValue = (uint)0xFFFFFFFF;
                        nRet = DeviceIoControl(hIoCtrl, (UInt32)IOCTL_STORAGE_QUERY_PROPERTY, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);
                    }

                    if (nRet == false)
                    {
                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    nptwb = (TStorageQueryWithBuffer)Marshal.PtrToStructure(inpBuffer, typeof(TStorageQueryWithBuffer));

                    hIoCtrl.Close();
                    Marshal.Copy(nptwb.Buffer, 0, data, Marshal.SizeOf(typeof(NVMe_SMART_DATA)));
                    /*
                    NVME_IDENTIFY_DEVICE test = (NVME_IDENTIFY_DEVICE)Marshal.PtrToStructure(data, typeof(NVME_IDENTIFY_DEVICE));
                    string Model = new string(test.Model);
                    */
                    return nRet;
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
            }

            /// <summary>
            /// NVMe DeviceSelfTest。
            /// <param name="filename">磁碟 Ex: "\\\\.\\PHYSICALDRIVE2"</param>
            /// <param name="_iAction">1h: start short test, 2h: start extended test, Fh: abort test</param>
            /// </summary>
            public static bool DeviceSelfTest(string filename, int _iAction)
            {
                //string filename = "\\\\.\\SCSI1:";
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;
                int inpBuffer_Length = Marshal.OffsetOf(typeof(STORAGE_PROTOCOL_COMMAND), "Command").ToInt32() + (int)STORAGE_PROTOCOL_COMMAND_LENGTH_NVME;
                IntPtr inpBuffer = Marshal.AllocHGlobal(inpBuffer_Length);

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    STORAGE_PROTOCOL_COMMAND pCmd = new STORAGE_PROTOCOL_COMMAND();
                    //pCmd.Length = (UInt32)Marshal.SizeOf(typeof(STORAGE_PROTOCOL_COMMAND));
                    pCmd.Length = 84;
                    pCmd.Version = STORAGE_PROTOCOL_STRUCTURE_VERSION;
                    pCmd.ProtocolType = TStroageProtocolType.ProtocolTypeNvme;
                    pCmd.Flags = STORAGE_PROTOCOL_COMMAND_FLAG_ADAPTER_REQUEST;
                    pCmd.CommandLength = STORAGE_PROTOCOL_COMMAND_LENGTH_NVME;
                    pCmd.ErrorInfoLength = 0;
                    pCmd.ErrorInfoOffset = 0;
                    pCmd.DataFromDeviceBufferOffset = 0;
                    pCmd.DataFromDeviceTransferLength = 0;
                    pCmd.TimeOutValue = 10;
                    pCmd.CommandSpecific = STORAGE_PROTOCOL_SPECIFIC_NVME_ADMIN_COMMAND;

                    pCmd.Command.CDW0 = (uint)NVME_ADMIN_COMMANDS.NVME_ADMIN_COMMAND_DEVICE_SELF_TEST;
                    pCmd.Command.NSID = NVME_NAMESPACE_ALL;
                    pCmd.Command.CDW10 = (uint)_iAction;  // 1h: start short test, 2h: start extended test, Fh: abort test

                    Int32 length = Marshal.SizeOf(pCmd);
                    uint dwReturned = 0;

                    Marshal.StructureToPtr(pCmd, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IOCTL_STORAGE_PROTOCOL_COMMAND, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    pCmd = (STORAGE_PROTOCOL_COMMAND)Marshal.PtrToStructure(inpBuffer, typeof(STORAGE_PROTOCOL_COMMAND));

                    hIoCtrl.Close();
                    //Marshal.Copy(nptwb.Buffer, 0, data, Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));
                    /*
                    NVME_IDENTIFY_DEVICE test = (NVME_IDENTIFY_DEVICE)Marshal.PtrToStructure(data, typeof(NVME_IDENTIFY_DEVICE));
                    string Model = new string(test.Model);
                    */
                    return nRet;
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
            }

            /// <summary>
            /// Get NVMe DeviceSelfTest Log。
            /// <param name="filename">磁碟 Ex: "\\\\.\\PHYSICALDRIVE2"</param>
            /// <param name="data">外部傳入 NVMe DeviceSelfTestLog 結構體存放指標</param>
            /// </summary>
            public static bool GetDeviceSelfTestLog(string filename, IntPtr data)
            {
                //string filename = "\\\\.\\SCSI1:";
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;
                int inpBuffer_Length = Marshal.SizeOf(typeof(TStorageQueryWithBuffer));
                IntPtr inpBuffer = Marshal.AllocHGlobal(inpBuffer_Length);

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    TStorageQueryWithBuffer nptwb = new TStorageQueryWithBuffer();

                    //nptwb.Query.PropertyId = TStoragePropertyId.StorageDeviceProtocolSpecificProperty;
                    nptwb.Query.PropertyId = TStoragePropertyId.StorageAdapterProtocolSpecificProperty;
                    nptwb.Query.QueryType = TStorageQueryType.PropertyStandardQuery;

                    nptwb.ProtocolSpecific.ProtocolType = TStroageProtocolType.ProtocolTypeNvme;
                    nptwb.ProtocolSpecific.DataType = (Int32)TStorageProtocolNVMeDataType.NVMeDataTypeLogPage;
                    nptwb.ProtocolSpecific.ProtocolDataOffset = Marshal.SizeOf(typeof(TStorageProtocolSpecificData));
                    nptwb.ProtocolSpecific.ProtocolDataLength = 4096;
                    nptwb.ProtocolSpecific.ProtocolDataRequestValue = (Int32)NVME_LOG_PAGES.NVME_LOG_PAGE_DEVICE_SELF_TEST;
                    nptwb.ProtocolSpecific.ProtocolDataRequestSubValue = 0;

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IOCTL_STORAGE_QUERY_PROPERTY, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        // Get the last error and display it.
                        int error = Marshal.GetLastWin32Error();
                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    nptwb = (TStorageQueryWithBuffer)Marshal.PtrToStructure(inpBuffer, typeof(TStorageQueryWithBuffer));

                    hIoCtrl.Close();
                    Marshal.Copy(nptwb.Buffer, 0, data, Marshal.SizeOf(typeof(NVME_DEVICE_SELF_TEST_LOG)));
                    return nRet;
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
            }
            #endregion
        }

        private class IntelNVMeOnboard : ExternBase
        {
            #region  NVMe Intel
            /*---------------------------------------------------------------------------*/
            // NVMe Intel 
            // Reference: http://naraeon.net/en/archives/1126
            /*---------------------------------------------------------------------------*/

            /// <summary>
            /// 取得 Identify資訊。
            /// </summary>
            public static bool DoIdentifyDevice(string filename, IntPtr data)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_PASS_THROUGH_IOCTL)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    NVME_PASS_THROUGH_IOCTL nptwb = new NVME_PASS_THROUGH_IOCTL();
                    nptwb.VendorSpecific = new Int32[NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE];
                    nptwb.CplEntry = new Int32[NVME_IOCTL_COMPLETE_DW_SIZE];
                    nptwb.NVMeCmd = new UInt32[NVME_IOCTL_CMD_DW_SIZE];
                    nptwb.DataBuffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    nptwb.SrbIoCtrl.ControlCode = NVME_PASS_THROUGH_SRB_IO_CODE;
                    nptwb.SrbIoCtrl.HeaderLength = Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.SrbIoCtrl.Signature = NVME_SIG_STR.ToCharArray();
                    nptwb.SrbIoCtrl.Timeout = NVME_PT_TIMEOUT;
                    nptwb.SrbIoCtrl.Length = length - Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.DataBufferLen = nptwb.DataBuffer.Length;
                    nptwb.ReturnBufferLen = Marshal.SizeOf(nptwb);
                    nptwb.Direction = NVME_FROM_DEV_TO_HOST;

                    nptwb.NVMeCmd[0] = 6;  // Identify
                    nptwb.NVMeCmd[10] = 1; // Return to Host



                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IO_CONTROL_CODE.IOCTL_SCSI_MINIPORT, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    nptwb = (NVME_PASS_THROUGH_IOCTL)Marshal.PtrToStructure(inpBuffer, typeof(NVME_PASS_THROUGH_IOCTL));
                    Int32 count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += nptwb.DataBuffer[i];
                    }

                    if (count == 0)
                    {

                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    hIoCtrl.Close();
                    Marshal.Copy(nptwb.DataBuffer, 0, data, Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));
                    /*
                    NVME_IDENTIFY_DEVICE test = (NVME_IDENTIFY_DEVICE)Marshal.PtrToStructure(data, typeof(NVME_IDENTIFY_DEVICE));
                    string Model = new string(test.Model);
                    */
                    return nRet;
                }
                catch (Exception ex)
                {

                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }

            }

            /// <summary>
            /// 取得 Identify NameSpace資訊。
            /// </summary>
            public static bool DoIdentifyNameSpaceDevice(string filename, IntPtr nvme_identufy_namespace_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_PASS_THROUGH_IOCTL)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    NVME_PASS_THROUGH_IOCTL nptwb = new NVME_PASS_THROUGH_IOCTL();
                    nptwb.VendorSpecific = new Int32[NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE];
                    nptwb.CplEntry = new Int32[NVME_IOCTL_COMPLETE_DW_SIZE];
                    nptwb.NVMeCmd = new UInt32[NVME_IOCTL_CMD_DW_SIZE];
                    nptwb.DataBuffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    nptwb.SrbIoCtrl.ControlCode = NVME_PASS_THROUGH_SRB_IO_CODE;
                    nptwb.SrbIoCtrl.HeaderLength = Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.SrbIoCtrl.Signature = NVME_SIG_STR.ToCharArray();
                    nptwb.SrbIoCtrl.Timeout = NVME_PT_TIMEOUT;
                    nptwb.SrbIoCtrl.Length = length - Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.DataBufferLen = nptwb.DataBuffer.Length;
                    nptwb.ReturnBufferLen = Marshal.SizeOf(nptwb);
                    nptwb.Direction = NVME_FROM_DEV_TO_HOST;

                    nptwb.NVMeCmd[0] = 6;  // OPCode - Identify
                    nptwb.NVMeCmd[1] = 1;  // NSID
                    nptwb.NVMeCmd[10] = 0; // CNS



                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IO_CONTROL_CODE.IOCTL_SCSI_MINIPORT, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    nptwb = (NVME_PASS_THROUGH_IOCTL)Marshal.PtrToStructure(inpBuffer, typeof(NVME_PASS_THROUGH_IOCTL));
                    Int32 count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += nptwb.DataBuffer[i];
                    }

                    if (count == 0)
                    {

                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    hIoCtrl.Close();
                    Marshal.Copy(nptwb.DataBuffer, 0, nvme_identufy_namespace_data_ptr, Marshal.SizeOf(typeof(NVME_IDENTIFY_NAMESPACE_DEVICE)));
                    /*
                    NVME_IDENTIFY_DEVICE test = (NVME_IDENTIFY_DEVICE)Marshal.PtrToStructure(data, typeof(NVME_IDENTIFY_DEVICE));
                    string Model = new string(test.Model);
                    */
                    return nRet;
                }
                catch (Exception ex)
                {

                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }

            }

            /// <summary>
            /// 取得 SMART資訊。
            /// </summary>
            public static bool GetSmartAttribute(string filename, IntPtr data)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_PASS_THROUGH_IOCTL)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    NVME_PASS_THROUGH_IOCTL nptwb = new NVME_PASS_THROUGH_IOCTL();
                    nptwb.VendorSpecific = new Int32[NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE];
                    nptwb.CplEntry = new Int32[NVME_IOCTL_COMPLETE_DW_SIZE];
                    nptwb.NVMeCmd = new UInt32[NVME_IOCTL_CMD_DW_SIZE];
                    nptwb.DataBuffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    nptwb.SrbIoCtrl.ControlCode = NVME_PASS_THROUGH_SRB_IO_CODE;
                    nptwb.SrbIoCtrl.HeaderLength = Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.SrbIoCtrl.Signature = NVME_SIG_STR.ToCharArray();
                    nptwb.SrbIoCtrl.Timeout = NVME_PT_TIMEOUT;
                    nptwb.SrbIoCtrl.Length = length - Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.DataBufferLen = nptwb.DataBuffer.Length;
                    nptwb.ReturnBufferLen = Marshal.SizeOf(nptwb);
                    nptwb.Direction = NVME_FROM_DEV_TO_HOST;

                    nptwb.NVMeCmd[0] = 2;  // GetLogPage
                    nptwb.NVMeCmd[1] = 0xFFFFFFFF;  // Scrop => All NameSpace
                    nptwb.NVMeCmd[10] = 0x007f0002; // SMART => 0x02



                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IO_CONTROL_CODE.IOCTL_SCSI_MINIPORT, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    nptwb = (NVME_PASS_THROUGH_IOCTL)Marshal.PtrToStructure(inpBuffer, typeof(NVME_PASS_THROUGH_IOCTL));
                    Int32 count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += nptwb.DataBuffer[i];
                    }

                    if (count == 0)
                    {

                        hIoCtrl.Close();
                        nRet = false;
                        return nRet;
                    }

                    hIoCtrl.Close();
                    Marshal.Copy(nptwb.DataBuffer, 0, data, Marshal.SizeOf(typeof(NVMe_SMART_DATA)));
                    /*
                    NVMe_SMART_DATA test = (NVMe_SMART_DATA)Marshal.PtrToStructure(data, typeof(NVMe_SMART_DATA));
                    */

                    return nRet;
                }
                catch (Exception ex)
                {

                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
            }

            /// <summary>
            /// NVMe 低階格式化 [同步執行]。
            /// </summary>
            public static bool FormatDevice(string filename)
            {
                // SCSI 穿透命令需要使用正確的 SCSI 設備地址作為 handle 參數 !!!
                //Track.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_PASS_THROUGH_IOCTL)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Track.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    NVME_PASS_THROUGH_IOCTL nptwb = new NVME_PASS_THROUGH_IOCTL();
                    nptwb.VendorSpecific = new Int32[NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE];
                    nptwb.CplEntry = new Int32[NVME_IOCTL_COMPLETE_DW_SIZE];
                    nptwb.NVMeCmd = new UInt32[NVME_IOCTL_CMD_DW_SIZE];
                    nptwb.DataBuffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    nptwb.SrbIoCtrl.ControlCode = NVME_PASS_THROUGH_SRB_IO_CODE;
                    nptwb.SrbIoCtrl.HeaderLength = Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.SrbIoCtrl.Signature = NVME_SIG_STR.ToCharArray();
                    nptwb.SrbIoCtrl.Timeout = NVME_PT_TIMEOUT;
                    nptwb.SrbIoCtrl.Length = length - Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.DataBufferLen = nptwb.DataBuffer.Length;
                    nptwb.ReturnBufferLen = Marshal.SizeOf(nptwb);
                    nptwb.Direction = NVME_FROM_DEV_TO_HOST;

                    nptwb.NVMeCmd[0] = 0x80;  // Admin
                    nptwb.NVMeCmd[1] = 0xFFFFFFFF;  // NSID // 所有命名空間
                    nptwb.NVMeCmd[10] = 0; // 格式化的LBA範圍

                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IO_CONTROL_CODE.IOCTL_SCSI_MINIPORT, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        int lastWin32Error = Marshal.GetLastWin32Error();
                        Track.WriteLine(string.Format(@"GetLastWin32Error: {0}", lastWin32Error));
                    }
                    hIoCtrl.Close();
                }
                catch (Exception ex)
                {
                    nRet = false;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
                return nRet;
            }

            /// <summary>
            /// NVMe 安全格式化 [異步執行，且很久才完成]。
            /// 完成後，機率性的作業系統才會刷新資訊，最好主動定時自己去刷新。
            /// </summary>
            public static bool SanitizeDevice(string filename)
            {
                // SCSI 穿透命令需要使用正確的 SCSI 設備地址作為 handle 參數 !!!
                //Track.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_PASS_THROUGH_IOCTL)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Track.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    NVME_PASS_THROUGH_IOCTL nptwb = new NVME_PASS_THROUGH_IOCTL();
                    nptwb.VendorSpecific = new Int32[NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE];
                    nptwb.CplEntry = new Int32[NVME_IOCTL_COMPLETE_DW_SIZE];
                    nptwb.NVMeCmd = new UInt32[NVME_IOCTL_CMD_DW_SIZE];
                    nptwb.DataBuffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    nptwb.SrbIoCtrl.ControlCode = NVME_PASS_THROUGH_SRB_IO_CODE;
                    nptwb.SrbIoCtrl.HeaderLength = Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.SrbIoCtrl.Signature = NVME_SIG_STR.ToCharArray();
                    nptwb.SrbIoCtrl.Timeout = NVME_PT_TIMEOUT;
                    nptwb.SrbIoCtrl.Length = length - Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.DataBufferLen = nptwb.DataBuffer.Length;
                    nptwb.ReturnBufferLen = Marshal.SizeOf(nptwb);
                    nptwb.Direction = NVME_FROM_DEV_TO_HOST;

                    nptwb.NVMeCmd[0] = 0x84;  // Sanitize (0x84) Admin
                    nptwb.NVMeCmd[1] = 0;
                    nptwb.NVMeCmd[10] = 0x0A; // Sanitize 操作的參數， 0 => 保留 / 1 => 退出 失敗的Erase / 2 => 啟動塊擦除清理操作 / 3 => 啟動覆蓋清理操作 / 4 => 啟動加密擦除清理操作 / 0x0A => (啟動塊擦除清理操作 + 無限制完成模式)
                    nptwb.NVMeCmd[11] = 0;  //  除非 Command Dword 10 中的 Sanitize Action 字段設置為 011b（即覆蓋），否則該字段將被忽略。 該字段指定用於覆蓋清理操作的 32 位模式。

                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IO_CONTROL_CODE.IOCTL_SCSI_MINIPORT, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        int lastWin32Error = Marshal.GetLastWin32Error();
                        Track.WriteLine(string.Format(@"GetLastWin32Error: {0}", lastWin32Error));
                    }
                    hIoCtrl.Close();
                }
                catch (Exception ex)
                {
                    nRet = false;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
                return nRet;
            }

            /// <summary>
            /// NVMe DeviceSelfTest。
            /// <param name="filename">磁碟 Ex: "\\\\.\\SCSI1:"</param>
            /// <param name="_iAction">1h: start short test, 2h: start extended test, Fh: abort test</param>
            /// </summary>
            public static bool DeviceSelfTest(string filename, int _iAction)
            {
                // SCSI 穿透命令需要使用正確的 SCSI 設備地址作為 handle 參數 !!!
                //Track.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_PASS_THROUGH_IOCTL)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Track.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    NVME_PASS_THROUGH_IOCTL nptwb = new NVME_PASS_THROUGH_IOCTL();
                    nptwb.VendorSpecific = new Int32[NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE];
                    nptwb.CplEntry = new Int32[NVME_IOCTL_COMPLETE_DW_SIZE];
                    nptwb.NVMeCmd = new UInt32[NVME_IOCTL_CMD_DW_SIZE];
                    nptwb.DataBuffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    nptwb.SrbIoCtrl.ControlCode = NVME_PASS_THROUGH_SRB_IO_CODE;
                    nptwb.SrbIoCtrl.HeaderLength = Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.SrbIoCtrl.Signature = NVME_SIG_STR.ToCharArray();
                    nptwb.SrbIoCtrl.Timeout = NVME_PT_TIMEOUT;
                    nptwb.SrbIoCtrl.Length = length - Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.DataBufferLen = nptwb.DataBuffer.Length;
                    nptwb.ReturnBufferLen = Marshal.SizeOf(nptwb);
                    nptwb.Direction = NVME_FROM_DEV_TO_HOST;

                    nptwb.NVMeCmd[0] = (uint)NVME_ADMIN_COMMANDS.NVME_ADMIN_COMMAND_DEVICE_SELF_TEST;
                    nptwb.NVMeCmd[1] = NVME_NAMESPACE_ALL;
                    nptwb.NVMeCmd[10] = (uint)_iAction;  // 1h: start short test, 2h: start extended test, Fh: abort test

                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IO_CONTROL_CODE.IOCTL_SCSI_MINIPORT, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        int lastWin32Error = Marshal.GetLastWin32Error();
                        Track.WriteLine(string.Format(@"GetLastWin32Error: {0}", lastWin32Error));
                    }
                    else
                    {
                        nptwb = (NVME_PASS_THROUGH_IOCTL)Marshal.PtrToStructure(inpBuffer, typeof(NVME_PASS_THROUGH_IOCTL));
                    }
                    hIoCtrl.Close();
                }
                catch (Exception ex)
                {
                    nRet = false;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
                return nRet;
            }

            /// <summary>
            /// Get NVMe DeviceSelfTest Log。
            /// <param name="filename">磁碟 Ex: "\\\\.\\SCSI1:"</param>
            /// <param name="data">外部傳入 NVMe DeviceSelfTestLog 結構體存放指標</param>
            /// </summary>
            public static bool GetDeviceSelfTestLog(string filename, IntPtr data)
            {
                // SCSI 穿透命令需要使用正確的 SCSI 設備地址作為 handle 參數 !!!
                //Track.WriteLine("Device PAth: " + filename);
                bool nRet = false;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(NVME_PASS_THROUGH_IOCTL)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\SCSI1:";
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Track.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    NVME_PASS_THROUGH_IOCTL nptwb = new NVME_PASS_THROUGH_IOCTL();
                    nptwb.VendorSpecific = new Int32[NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE];
                    nptwb.CplEntry = new Int32[NVME_IOCTL_COMPLETE_DW_SIZE];
                    nptwb.NVMeCmd = new UInt32[NVME_IOCTL_CMD_DW_SIZE];
                    nptwb.DataBuffer = new Byte[4096];

                    Int32 length = Marshal.SizeOf(nptwb);
                    uint dwReturned = 0;

                    nptwb.SrbIoCtrl.ControlCode = NVME_PASS_THROUGH_SRB_IO_CODE;
                    nptwb.SrbIoCtrl.HeaderLength = Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.SrbIoCtrl.Signature = NVME_SIG_STR.ToCharArray();
                    nptwb.SrbIoCtrl.Timeout = NVME_PT_TIMEOUT;
                    nptwb.SrbIoCtrl.Length = length - Marshal.SizeOf(typeof(SRB_IO_CONTROL));
                    nptwb.DataBufferLen = nptwb.DataBuffer.Length;
                    nptwb.ReturnBufferLen = Marshal.SizeOf(nptwb);
                    nptwb.Direction = NVME_FROM_DEV_TO_HOST;

                    nptwb.NVMeCmd[0] = 2;  // GetLogPage
                    nptwb.NVMeCmd[1] = 0xFFFFFFFF;  // Scrop => All NameSpace
                    nptwb.NVMeCmd[10] = 0x007f0006; // Device Self-test => 0x06

                    Marshal.StructureToPtr(nptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, (UInt32)IO_CONTROL_CODE.IOCTL_SCSI_MINIPORT, inpBuffer, (uint)length, inpBuffer, (uint)length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        int lastWin32Error = Marshal.GetLastWin32Error();
                        Track.WriteLine(string.Format(@"GetLastWin32Error: {0}", lastWin32Error));
                    }else
                    {
                        nptwb = (NVME_PASS_THROUGH_IOCTL)Marshal.PtrToStructure(inpBuffer, typeof(NVME_PASS_THROUGH_IOCTL));
                        Marshal.Copy(nptwb.DataBuffer, 0, data, Marshal.SizeOf(typeof(NVME_DEVICE_SELF_TEST_LOG)));
                    }
                    hIoCtrl.Close();
                }
                catch (Exception ex)
                {
                    nRet = false;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
                return nRet;
            }
            #endregion
        }
        #endregion

        #region SCSI Read Write
        public class SCSI_IO
        {
            /// <summary>
            /// Read LBA。
            /// </summary>
            /// <param name="filename">Ex: "\\\\.\\PHYSICALDRIVE2"。 注意不可用 "\\\\.\\SCSI1:"</param>
            /// <param name="startLBA">起始 LBA 地址</param>
            /// <param name="data">Buffer區塊 ，請勿超過 4096 Bytes。</param>
            /// <param name="len">要傳輸的 LBA 長度</param>
            public static bool Read_LBA(string filename, UInt64 startLBA, byte[] data, int len)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;
                uint length = 0;
                uint dwReturned = 0;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = (byte)sptwb.SenseBuf.Length;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 4096;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 10;
                    sptwb.Spt.Cdb[0] = 0x28; // SCSIOP_READ
                    sptwb.Spt.Cdb[2] = (byte)(startLBA >> 24);
                    sptwb.Spt.Cdb[3] = (byte)(startLBA >> 16);
                    sptwb.Spt.Cdb[4] = (byte)(startLBA >> 8);
                    sptwb.Spt.Cdb[5] = (byte)startLBA;
                    sptwb.Spt.Cdb[7] = (byte)(len >> 8);
                    sptwb.Spt.Cdb[8] = (byte)len;


                    length = (uint)((UInt32)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32()) + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        int error = Marshal.GetLastWin32Error();
                        nRet = false;
                        return nRet;
                    }

                    sptwb = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    hIoCtrl.Close();
                    Array.Copy(sptwb.DataBuf, 0, data, 0, data.Length);
                    /*
                    NVME_IDENTIFY_DEVICE test = (NVME_IDENTIFY_DEVICE)Marshal.PtrToStructure(data, typeof(NVME_IDENTIFY_DEVICE));
                    string Model = new string(test.Model);
                    */
                    return nRet;
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
            }

            /// <summary>
            /// Write LBA。
            /// </summary>
            /// <param name="filename">Ex: "\\\\.\\PHYSICALDRIVE2"。 注意不可用 "\\\\.\\SCSI1:"</param>
            /// <param name="startLBA">起始 LBA 地址</param>
            /// <param name="data">Buffer區塊 ，請勿超過 4096 Bytes。</param>
            /// <param name="len">要傳輸的 LBA 長度</param>
            public static bool Write_LBA(string filename, UInt64 startLBA, byte[] data, int len)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool nRet = false;
                uint length = 0;
                uint dwReturned = 0;

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //設置的有關GPIO的全局變量
                    //filename = "\\\\.\\PhysicalDrive1";
                    SafeFileHandle hIoCtrl = CreateFileW(filename,
                                        GENERIC_READ | GENERIC_WRITE, // Administrative privilege is required
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        OPEN_EXISTING,
                                        FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                    if (hIoCtrl == null || hIoCtrl.IsInvalid)
                    {
                        Console.WriteLine("連接GPIO設備失敗");
                        return false;
                    }

                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = (byte)sptwb.SenseBuf.Length;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = 4096;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 10;
                    sptwb.Spt.Cdb[0] = 0x2A; // SCSIOP_WRITE
                    sptwb.Spt.Cdb[2] = (byte)(startLBA >> 24);
                    sptwb.Spt.Cdb[3] = (byte)(startLBA >> 16);
                    sptwb.Spt.Cdb[4] = (byte)(startLBA >> 8);
                    sptwb.Spt.Cdb[5] = (byte)startLBA;
                    sptwb.Spt.Cdb[7] = (byte)(len >> 8);
                    sptwb.Spt.Cdb[8] = (byte)len;

                    Array.Copy(data, 0, sptwb.DataBuf, 0, data.Length);


                    length = (uint)((UInt32)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32()) + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    nRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (nRet == false)
                    {
                        int error = Marshal.GetLastWin32Error();
                        nRet = false;
                        return nRet;
                    }

                    sptwb = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    hIoCtrl.Close();
                    Array.Copy(sptwb.DataBuf, 0, data, 0, data.Length);
                    /*
                    NVME_IDENTIFY_DEVICE test = (NVME_IDENTIFY_DEVICE)Marshal.PtrToStructure(data, typeof(NVME_IDENTIFY_DEVICE));
                    string Model = new string(test.Model);
                    */
                    return nRet;
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    nRet = false;
                    return nRet;
                }
                finally
                {
                    Marshal.FreeHGlobal(inpBuffer);
                    inpBuffer = IntPtr.Zero;
                }
            }
        }


        #endregion

        #region USB Bridge Control

        private class ASMediaNVMeBridge : ExternBase
        {
            #region ASMedia
            // ASMedia USB Bridge 相關
            public static bool DoIdentifyDevice(string filename, IntPtr nvme_identufy_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_identufy_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 4096;
                    sptwb.Spt.TimeOutValue = 3;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xE6; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x06; // IDENTIFY
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0x01;
                    sptwb.Spt.Cdb[4] = 0;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_identufy_data_ptr, Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            /// <summary>
            /// 取得 Identify NameSpace資訊。
            /// </summary>
            public static bool DoIdentifyNameSpaceDevice(string filename, IntPtr nvme_identufy_namespace_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_identufy_namespace_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_namespace_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 4096;
                    sptwb.Spt.TimeOutValue = 3;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    //  備註: ASMedia 製具這裡，沒有選擇NSID。是因為 說明文件中，並未有此選項。描述是給預設值可以直接用。
                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xE6; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x06; // NVMe Opcode - IDENTIFY
                    sptwb.Spt.Cdb[2] = 0;    // Reserved
                    sptwb.Spt.Cdb[3] = 0x00; // CNS (0 => Identify Namespace data structure / 1 => Identify Controller data structure)
                    sptwb.Spt.Cdb[4] = 0;    // cdb[4~15] Reserved
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_identufy_namespace_data_ptr, Marshal.SizeOf(typeof(NVME_IDENTIFY_NAMESPACE_DEVICE)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool GetSmartAttribute(string filename, IntPtr nvme_smart_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_smart_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_smart_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xE6; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x02; // GetLogPage
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0x02; // S.M.A.R.T.
                    sptwb.Spt.Cdb[4] = 0;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0x7F;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_smart_data_ptr, Marshal.SizeOf(typeof(NVMe_SMART_DATA)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool FormatDevice(string filename)
            {

                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Track.WriteLine("連接GPIO設備失敗 : {0}", filename);
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT)));

                try
                {
                    #region 第一階段
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = 64;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xEA;    // NVMe Packet Passthrough(ASMedia) Cdb 部分詳見 ASMedia Vendor Spec
                    sptwb.Spt.Cdb[1] = 0x5A;    // Signature
                    sptwb.Spt.Cdb[2] = 0x80;    // Operation Code 
                    sptwb.Spt.Cdb[3] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[4] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[5] = 0;       // Cdb[5~9] Reseved (00h)
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;      // Cdb[10~13] Allocation Length (MSB -> LSB)
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.Spt.Cdb[12] = 0;
                    sptwb.Spt.Cdb[13] = 0x40;
                    sptwb.Spt.Cdb[14] = 0;      // Cdb[14~15] Reseved (00h)
                    sptwb.Spt.Cdb[15] = 0;

                    sptwb.DataBuf_Alias_UInt32[0] = 0x80;
                    sptwb.DataBuf_Alias_UInt32[1] = 0xFFFFFFFF;
                    sptwb.DataBuf_Alias_UInt32[10] = 0x200; // DW 10
                    sptwb.DataBuf_Alias_UInt32[11] = 0; // DW 11
                    sptwb.DataBuf_Alias_UInt32[12] = 0; // DW 12
                    sptwb.DataBuf_Alias_UInt32[13] = 0; // DW 13
                    sptwb.DataBuf_Alias_UInt32[14] = 0; // DW 14
                    sptwb.DataBuf_Alias_UInt32[15] = 0; // DW 15

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================
                    #endregion

                    #region 第二階段
                    //============== 第二階段  Start ====================================
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_UNSPECIFIED;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xEB;    // NVMe Packet Passthrough(ASMedia) Cdb 部分詳見 ASMedia Vendor Spec
                    sptwb.Spt.Cdb[1] = 0x5A;    // Signature
                    sptwb.Spt.Cdb[2] = 0x81;       // Operation
                    sptwb.Spt.Cdb[3] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[4] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[5] = 0;       // Cdb[5~9] Reseved (00h)
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;      // Cdb[10~13] Allocation Length (MSB -> LSB)
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.Spt.Cdb[12] = 0;
                    sptwb.Spt.Cdb[13] = 0;
                    sptwb.Spt.Cdb[14] = 0;      // Cdb[14~15] Reseved (00h)
                    sptwb.Spt.Cdb[15] = 0;

                    sptwb.DataBuf_Alias_UInt32[0] = 0; // DW 0
                    sptwb.DataBuf_Alias_UInt32[1] = 0; // DW 1
                    sptwb.DataBuf_Alias_UInt32[10] = 0; // DW 10
                    sptwb.DataBuf_Alias_UInt32[11] = 0; // DW 11
                    sptwb.DataBuf_Alias_UInt32[12] = 0; // DW 12
                    sptwb.DataBuf_Alias_UInt32[13] = 0; // DW 13
                    sptwb.DataBuf_Alias_UInt32[14] = 0; // DW 14
                    sptwb.DataBuf_Alias_UInt32[15] = 0; // DW 15

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第二階段  End ====================================
                    #endregion

                    #region 第三階段
                    //============== 第三階段  Start ====================================
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 16;
                    sptwb.Spt.TimeOutValue = 30;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xEB;    // NVMe Packet Passthrough(ASMedia) Cdb 部分詳見 ASMedia Vendor Spec
                    sptwb.Spt.Cdb[1] = 0x5A;    // Signature
                    sptwb.Spt.Cdb[2] = 0x82;       // Operation
                    sptwb.Spt.Cdb[3] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[4] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[5] = 0;       // Cdb[5~9] Reseved (00h)
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;      // Cdb[10~13] Allocation Length (MSB -> LSB)
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.Spt.Cdb[12] = 0;
                    sptwb.Spt.Cdb[13] = 0x10;
                    sptwb.Spt.Cdb[14] = 0;      // Cdb[14~15] Reseved (00h)
                    sptwb.Spt.Cdb[15] = 0;

                    sptwb.DataBuf_Alias_UInt32[0] = 0; // DW 0
                    sptwb.DataBuf_Alias_UInt32[1] = 0; // DW 1
                    sptwb.DataBuf_Alias_UInt32[10] = 0; // DW 10
                    sptwb.DataBuf_Alias_UInt32[11] = 0; // DW 11
                    sptwb.DataBuf_Alias_UInt32[12] = 0; // DW 12
                    sptwb.DataBuf_Alias_UInt32[13] = 0; // DW 13
                    sptwb.DataBuf_Alias_UInt32[14] = 0; // DW 14
                    sptwb.DataBuf_Alias_UInt32[15] = 0; // DW 15

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第三階段  End ====================================
                    #endregion

                    SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT));

                    byte[] tempBytes = BitConverter.GetBytes(sptwb_result.DataBuf_Alias_UInt32[3]);

                    if (tempBytes[2] == 0xFF || tempBytes[3] == 0xFF)
                    {
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        // 沒有回傳東西
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool SanitizeDevice(string filename)
            {

                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Track.WriteLine("連接GPIO設備失敗 : {0}", filename);
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT)));

                try
                {
                    #region 第一階段
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = 64;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xEA;    // NVMe Packet Passthrough(ASMedia) Cdb 部分詳見 ASMedia Vendor Spec
                    sptwb.Spt.Cdb[1] = 0x5A;    // Signature
                    sptwb.Spt.Cdb[2] = 0x80;    // Operation Code 
                    sptwb.Spt.Cdb[3] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[4] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[5] = 0;       // Cdb[5~9] Reseved (00h)
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;      // Cdb[10~13] Allocation Length (MSB -> LSB)
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.Spt.Cdb[12] = 0;
                    sptwb.Spt.Cdb[13] = 0x40;
                    sptwb.Spt.Cdb[14] = 0;      // Cdb[14~15] Reseved (00h)
                    sptwb.Spt.Cdb[15] = 0;

                    sptwb.DataBuf_Alias_UInt32[0] = 0x84;   //  OPCode Sanitize command
                    sptwb.DataBuf_Alias_UInt32[1] = 0;
                    sptwb.DataBuf_Alias_UInt32[10] = 0x02; // DW 10 // Block Erase
                    sptwb.DataBuf_Alias_UInt32[11] = 0; // DW 11
                    sptwb.DataBuf_Alias_UInt32[12] = 0; // DW 12
                    sptwb.DataBuf_Alias_UInt32[13] = 0; // DW 13
                    sptwb.DataBuf_Alias_UInt32[14] = 0; // DW 14
                    sptwb.DataBuf_Alias_UInt32[15] = 0; // DW 15

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================
                    #endregion

                    #region 第二階段
                    //============== 第二階段  Start ====================================
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_UNSPECIFIED;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xEB;    // NVMe Packet Passthrough(ASMedia) Cdb 部分詳見 ASMedia Vendor Spec
                    sptwb.Spt.Cdb[1] = 0x5A;    // Signature
                    sptwb.Spt.Cdb[2] = 0x81;       // Operation
                    sptwb.Spt.Cdb[3] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[4] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[5] = 0;       // Cdb[5~9] Reseved (00h)
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;      // Cdb[10~13] Allocation Length (MSB -> LSB)
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.Spt.Cdb[12] = 0;
                    sptwb.Spt.Cdb[13] = 0;
                    sptwb.Spt.Cdb[14] = 0;      // Cdb[14~15] Reseved (00h)
                    sptwb.Spt.Cdb[15] = 0;

                    sptwb.DataBuf_Alias_UInt32[0] = 0; // DW 0
                    sptwb.DataBuf_Alias_UInt32[1] = 0; // DW 1
                    sptwb.DataBuf_Alias_UInt32[10] = 0; // DW 10
                    sptwb.DataBuf_Alias_UInt32[11] = 0; // DW 11
                    sptwb.DataBuf_Alias_UInt32[12] = 0; // DW 12
                    sptwb.DataBuf_Alias_UInt32[13] = 0; // DW 13
                    sptwb.DataBuf_Alias_UInt32[14] = 0; // DW 14
                    sptwb.DataBuf_Alias_UInt32[15] = 0; // DW 15

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第二階段  End ====================================
                    #endregion

                    #region 第三階段
                    //============== 第三階段  Start ====================================
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 16;
                    sptwb.Spt.TimeOutValue = 30;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xEB;    // NVMe Packet Passthrough(ASMedia) Cdb 部分詳見 ASMedia Vendor Spec
                    sptwb.Spt.Cdb[1] = 0x5A;    // Signature
                    sptwb.Spt.Cdb[2] = 0x82;       // Operation
                    sptwb.Spt.Cdb[3] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[4] = 0;       // Parameter 1
                    sptwb.Spt.Cdb[5] = 0;       // Cdb[5~9] Reseved (00h)
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;      // Cdb[10~13] Allocation Length (MSB -> LSB)
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.Spt.Cdb[12] = 0;
                    sptwb.Spt.Cdb[13] = 0x10;
                    sptwb.Spt.Cdb[14] = 0;      // Cdb[14~15] Reseved (00h)
                    sptwb.Spt.Cdb[15] = 0;

                    sptwb.DataBuf_Alias_UInt32[0] = 0; // DW 0
                    sptwb.DataBuf_Alias_UInt32[1] = 0; // DW 1
                    sptwb.DataBuf_Alias_UInt32[10] = 0; // DW 10
                    sptwb.DataBuf_Alias_UInt32[11] = 0; // DW 11
                    sptwb.DataBuf_Alias_UInt32[12] = 0; // DW 12
                    sptwb.DataBuf_Alias_UInt32[13] = 0; // DW 13
                    sptwb.DataBuf_Alias_UInt32[14] = 0; // DW 14
                    sptwb.DataBuf_Alias_UInt32[15] = 0; // DW 15

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第三階段  End ====================================
                    #endregion

                    SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT));

                    byte[] tempBytes = BitConverter.GetBytes(sptwb_result.DataBuf_Alias_UInt32[3]);

                    if (tempBytes[2] == 0xFF || tempBytes[3] == 0xFF)
                    {
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        // 沒有回傳東西
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool Set_Bridge_Power(string filename, uint powerState)
            {

                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;
                int lastWin32Error = 0;

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Track.WriteLine("連接GPIO設備失敗 : {0}", filename);
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT)));

                try
                {
                    SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 32;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_UNSPECIFIED;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xEF;    // NVMe Packet Passthrough(ASMedia) Cdb 部分詳見 ASMedia Vendor Spec
                    sptwb.Spt.Cdb[1] = 0x17;    // Signature
                    sptwb.Spt.Cdb[2] = 0x4C;    // Operation Code 
                    sptwb.Spt.Cdb[3] = (byte)powerState;       // Parameter 1 //  NVMe Power State
                    sptwb.Spt.Cdb[4] = 0;       // Parameter 2  
                    sptwb.Spt.Cdb[5] = 0;       // Cdb[5~9] Reseved (00h)
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;      // Cdb[10~13] Allocation Length (MSB -> LSB)
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.Spt.Cdb[12] = 0;
                    sptwb.Spt.Cdb[13] = 0;
                    sptwb.Spt.Cdb[14] = 0;      // Cdb[14~15] Reseved (00h)
                    sptwb.Spt.Cdb[15] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_UINT_TYPE_DIRECT), "DataBuf_Alias_UInt32").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);
                    lastWin32Error = Marshal.GetLastWin32Error();
                    if (bRet == false || lastWin32Error != 0)
                    {
                        Track.WriteLine(string.Format(@"GetLastWin32Error: {0}", lastWin32Error));
                        bRet = false;
                    }
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }
            #endregion
        }

        private class JMicronNVMeBridge
        {
            #region JMicron

            // JMicron USB Bridge 相關
            public static bool DoIdentifyDevice(string filename, IntPtr nvme_identufy_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_identufy_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 3;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x80; // ADMIN
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 2;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.DataBuf[0] = Convert.ToByte('N');
                    sptwb.DataBuf[1] = Convert.ToByte('V');
                    sptwb.DataBuf[2] = Convert.ToByte('M');
                    sptwb.DataBuf[3] = Convert.ToByte('E');
                    sptwb.DataBuf[8] = 0x06; // Identify
                    sptwb.DataBuf[0x30] = 0x01;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================

                    //============== 第二階段  Start ====================================
                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 4096;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x82; // ADMIN + DMA-IN
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 16;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第二階段  End ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT));

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_identufy_data_ptr, Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            /// <summary>
            /// 取得 Identify NameSpace資訊。
            /// </summary>
            public static bool DoIdentifyNameSpaceDevice(string filename, IntPtr nvme_identufy_namespace_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_identufy_namespace_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_namespace_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 3;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x80; // ADMIN
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 2;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.DataBuf[0] = Convert.ToByte('N');
                    sptwb.DataBuf[1] = Convert.ToByte('V');
                    sptwb.DataBuf[2] = Convert.ToByte('M');
                    sptwb.DataBuf[3] = Convert.ToByte('E');
                    // ---- CDW0 [8 ~ 11] ----
                    sptwb.DataBuf[8] = 0x06; // Identify
                    //-------------------------
                    // ---- NSID [12 ~ 15] ----
                    //sptwb.DataBuf[12] = 0xFF;
                    //sptwb.DataBuf[13] = 0xFF;
                    //sptwb.DataBuf[14] = 0xFF;
                    //sptwb.DataBuf[15] = 0xFF;
                    sptwb.DataBuf[12] = 0x01;
                    //-------------------------
                    // ---- CDW10 [48~51]
                    sptwb.DataBuf[48] = 0x00;   // 該字段指定要返回給主機的資訊。 [0 -> Identify Namespace data structure / 1 -> Identify Controller data structure]
                    //-------------------------

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================

                    //============== 第二階段  Start ====================================
                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x82; // ADMIN + DMA-IN
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 2;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第二階段  End ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT));

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_identufy_namespace_data_ptr, Marshal.SizeOf(typeof(NVME_IDENTIFY_NAMESPACE_DEVICE)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool GetSmartAttribute(string filename, IntPtr nvme_smart_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_smart_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_smart_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = SMART_LOG_SECTOR_SIZE;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x80; // ADMIN
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 2;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;
                    sptwb.DataBuf[0] = Convert.ToByte('N');
                    sptwb.DataBuf[1] = Convert.ToByte('V');
                    sptwb.DataBuf[2] = Convert.ToByte('M');
                    sptwb.DataBuf[3] = Convert.ToByte('E');
                    sptwb.DataBuf[8] = 0x02;  // GetLogPage, S.M.A.R.T.
                    sptwb.DataBuf[10] = 0x56;
                    sptwb.DataBuf[12] = 0xFF;
                    sptwb.DataBuf[13] = 0xFF;
                    sptwb.DataBuf[14] = 0xFF;
                    sptwb.DataBuf[15] = 0xFF;
                    sptwb.DataBuf[0x21] = 0x40;
                    sptwb.DataBuf[0x22] = 0x7A;
                    sptwb.DataBuf[0x30] = 0x02;
                    sptwb.DataBuf[0x32] = 0x7F;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================

                    //============== 第二階段  Start ====================================
                    sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = SMART_LOG_SECTOR_SIZE;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x82; // ADMIN + DMA-IN
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 2;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第二階段  End ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_smart_data_ptr, Marshal.SizeOf(typeof(NVMe_SMART_DATA)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool FormatDevice(string filename)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)));
                int Command_SECTOR_SIZE = 512;
                try
                {
                    //============== 第一階段  Start ====================================
                    // 第一階段下 NVM PASS-THROUGH command - NVM Command Set Payload Format
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;                     //  告知作業系統 結構體中的'SenseBuf'長度
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;       //  告知作業系統 有 Data Buffer 送出
                    sptwb.Spt.DataTransferLength = Command_SECTOR_SIZE; //  告知作業系統 交互的 Data Buffer 長度
                    sptwb.Spt.TimeOutValue = 10;                        //  Timeout 時間
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");  //  告知作業系統當前結構體的 'DataBuf' 記憶體起始位址
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32(); //  告知作業系統當前結構體的 'SenseBuf' 記憶體起始位址

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;    // JMS583自定義的  SCSI NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x80;    // JMS583自定義的  (ADMIN + NVMe Command Set Payload) 
                    sptwb.Spt.Cdb[2] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[3] = 0;       // JMS583自定義的 告知 JMS583 要傳遞的'DataBuffer'長度 (23:16)高位元 
                    sptwb.Spt.Cdb[4] = 0x02;    // JMS583自定義的 告知 JMS583 要傳遞的'DataBuffer'長度 (15:08)中位元 
                    sptwb.Spt.Cdb[5] = 0;       // JMS583自定義的 告知 JMS583 要傳遞的'DataBuffer'長度 (07:00)低位元 
                    sptwb.Spt.Cdb[6] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[7] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[8] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[9] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[10] = 0;      // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[11] = 0;      // JMS583文件未詳細解釋的功能
                    sptwb.DataBuf_Alias_UInt32[0] = 0x454d564e; // JMS583自定義的 NVME 字樣
                    sptwb.DataBuf_Alias_UInt32[2] = 0x80;       // JMS583自定義的 Opcodes for Admin Commands - Format. (CDW0)
                    sptwb.DataBuf_Alias_UInt32[3] = 0xFFFFFFFF; // JMS583自定義的 NSID
                    sptwb.DataBuf_Alias_UInt32[7] = 0x200;      // JMS583自定義的 (CDW10)

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================

                    //============== 第二階段  Start ====================================
                    sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_UNSPECIFIED;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x81; // ADMIN + Non-data
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 0;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第二階段  End ====================================

                    //============== 第三階段  Start ====================================
                    sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = Command_SECTOR_SIZE;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x8F; // ADMIN + Return Response Information
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 0x02;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第三階段  End ====================================

                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        bRet = false;
                        return bRet;
                    }
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool SanitizeDevice(string filename)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)));
                int Command_SECTOR_SIZE = 512;
                try
                {
                    //============== 第一階段  Start ====================================
                    // 第一階段下 NVM PASS-THROUGH command - NVM Command Set Payload Format
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;                     //  告知作業系統 結構體中的'SenseBuf'長度
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;       //  告知作業系統 有 Data Buffer 送出
                    sptwb.Spt.DataTransferLength = Command_SECTOR_SIZE; //  告知作業系統 交互的 Data Buffer 長度
                    sptwb.Spt.TimeOutValue = 10;                        //  Timeout 時間
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");  //  告知作業系統當前結構體的 'DataBuf' 記憶體起始位址
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32(); //  告知作業系統當前結構體的 'SenseBuf' 記憶體起始位址

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1;    // JMS583自定義的  SCSI NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x80;    // JMS583自定義的  (ADMIN + NVMe Command Set Payload) 
                    sptwb.Spt.Cdb[2] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[3] = 0;       // JMS583自定義的 告知 JMS583 要傳遞的'DataBuffer'長度 (23:16)高位元 
                    sptwb.Spt.Cdb[4] = 0x02;    // JMS583自定義的 告知 JMS583 要傳遞的'DataBuffer'長度 (15:08)中位元 
                    sptwb.Spt.Cdb[5] = 0;       // JMS583自定義的 告知 JMS583 要傳遞的'DataBuffer'長度 (07:00)低位元 
                    sptwb.Spt.Cdb[6] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[7] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[8] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[9] = 0;       // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[10] = 0;      // JMS583自定義的 保留區間
                    sptwb.Spt.Cdb[11] = 0;      // JMS583文件未詳細解釋的功能
                    sptwb.DataBuf_Alias_UInt32[0] = 0x454d564e; // JMS583自定義的 NVME 字樣
                    sptwb.DataBuf_Alias_UInt32[2] = 0x84;       // JMS583自定義的 Opcodes for Admin Commands - Sanitize. (CDW0)
                    sptwb.DataBuf_Alias_UInt32[3] = 0;          // JMS583自定義的 NSID
                    sptwb.DataBuf_Alias_UInt32[7] = 0x02;      // JMS583自定義的 (CDW10)

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================

                    //============== 第二階段  Start ====================================
                    sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_UNSPECIFIED;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x81; // ADMIN + Non-data
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 0;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第二階段  End ====================================

                    //============== 第三階段  Start ====================================
                    sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_UINT_TYPE_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf_Alias_UInt32 = new UInt32[1024];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = Command_SECTOR_SIZE;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xA1; // NVME PASS THROUGH
                    sptwb.Spt.Cdb[1] = 0x8F; // ADMIN + Return Response Information
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 0x02;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第三階段  End ====================================

                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        bRet = false;
                        return bRet;
                    }
                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            /// <summary>
            /// JMS583 + 特殊製具的 PS0 / PS3 功能。
            /// 註: 建議下命令前把，SSD 磁碟管理員 離線
            /// </summary>
            public static bool Set_Bridge_Power(string filename, uint powerState = 0)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT)));

                try
                {
                    SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT();
                    Console.WriteLine("設定電源 開始");
                    #region 設定電源 
                    //============== 第一階段  Start ==================================== 

                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[24];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 24;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_UNSPECIFIED;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "SenseBuf").ToInt32();

                    // USB SCSI Vendor Command for ASPM PS0/PS3
                    sptwb.Spt.CdbLength = 12;
                    sptwb.Spt.Cdb[0] = 0xFF;
                    sptwb.Spt.Cdb[1] = 0x06;
                    sptwb.Spt.Cdb[2] = 0;
                    sptwb.Spt.Cdb[3] = 0;
                    sptwb.Spt.Cdb[4] = 0;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    if (powerState == 0)
                    {
                        // PS0_Idle
                        sptwb.Spt.Cdb[3] = 0x00;
                    }
                    else if (powerState == 1)
                    {
                        // PS3_Idle
                        sptwb.Spt.Cdb[3] = 0x03;
                    }
                    else
                    {

                    }

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS24_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ==================================== 

                    #endregion
                    Console.WriteLine("設定電源 結束");
                    Thread.Sleep(1000);

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }
            #endregion
        }

        private class RealtekNVMeBridge
        {
            #region Realtek
            // Realtek USB Bridge 相關
            public static bool DoIdentifyDevice(string filename, IntPtr nvme_identufy_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_identufy_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 32;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 4096;
                    sptwb.Spt.TimeOutValue = 3;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xE4; // NVME READ
                    sptwb.Spt.Cdb[1] = 0x00; // ADMIN
                    sptwb.Spt.Cdb[2] = 0x10;
                    sptwb.Spt.Cdb[3] = 0x06; // IDENTIFY
                    sptwb.Spt.Cdb[4] = 0x01; // control struct
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_identufy_data_ptr, Marshal.SizeOf(typeof(NVME_IDENTIFY_DEVICE)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            /// <summary>
            /// 取得 Identify NameSpace資訊。
            /// </summary>
            public static bool DoIdentifyNameSpaceDevice(string filename, IntPtr nvme_identufy_namespace_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_identufy_namespace_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_identufy_namespace_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 32;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 4096;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xE4; // NVME READ
                    sptwb.Spt.Cdb[1] = 0x00; // ADMIN
                    sptwb.Spt.Cdb[2] = 0x10;
                    sptwb.Spt.Cdb[3] = 0x06; // IDENTIFY
                    sptwb.Spt.Cdb[4] = 0x00; // namespace struct
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_identufy_namespace_data_ptr, Marshal.SizeOf(typeof(NVME_IDENTIFY_NAMESPACE_DEVICE)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool GetSmartAttribute(string filename, IntPtr nvme_smart_data_ptr)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                if (nvme_smart_data_ptr == IntPtr.Zero)
                {
                    Console.WriteLine("nvme_smart_data_ptr 未傳入");
                    bRet = false;
                    return bRet;
                }

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 0;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 32;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_IN;
                    sptwb.Spt.DataTransferLength = 512;
                    sptwb.Spt.TimeOutValue = 10;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xE4; // NVME READ
                    sptwb.Spt.Cdb[1] = 0x00; // ADMIN
                    sptwb.Spt.Cdb[2] = 0x02;
                    sptwb.Spt.Cdb[3] = 0x02; // GetLogPage
                    sptwb.Spt.Cdb[4] = 0x00;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }
                    //============== 第一階段  End ====================================


                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb_result = (SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)Marshal.PtrToStructure(inpBuffer, typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT));

                    int count = 0;
                    for (int i = 0; i < 512; i++)
                    {
                        count += sptwb_result.DataBuf[i];
                    }
                    if (count == 0)
                    {
                        // 照抄 CDI，這個判斷不知為何。
                        bRet = false;
                        return bRet;
                    }

                    if (bRet == true)
                    {
                        // 最終結果
                        Marshal.Copy(sptwb_result.DataBuf, 0, nvme_smart_data_ptr, Marshal.SizeOf(typeof(NVMe_SMART_DATA)));
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }

            public static bool FormatDevice(string filename)
            {
                Console.WriteLine("Device PAth: " + filename);
                bool bRet = true;
                uint length = 0;
                uint dwReturned = 0;
                SafeFileHandle hIoCtrl;

                hIoCtrl = GetIoCtrlHandle(filename);

                if (hIoCtrl == null || hIoCtrl.IsInvalid)
                {
                    Console.WriteLine("連接GPIO設備失敗");
                    bRet = false;
                    return bRet;
                }

                IntPtr inpBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT)));

                try
                {
                    //============== 第一階段  Start ====================================
                    SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT sptwb = new SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT();
                    sptwb.Spt.Cdb = new byte[16];
                    sptwb.SenseBuf = new byte[32];
                    sptwb.DataBuf = new byte[4096];

                    sptwb.Spt.Length = (short)Marshal.SizeOf(typeof(SCSI_PASS_THROUGH_DIRECT)); ;
                    sptwb.Spt.PathId = 0;
                    sptwb.Spt.TargetId = 1;
                    sptwb.Spt.Lun = 0;
                    sptwb.Spt.SenseInfoLength = 32;
                    sptwb.Spt.DataIn = (byte)SCSI_IOCTL_DATA_OUT;
                    sptwb.Spt.DataTransferLength = 0;
                    sptwb.Spt.TimeOutValue = 65;
                    sptwb.Spt.DataBufferOffset = Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf");
                    sptwb.Spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "SenseBuf").ToInt32();

                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xE5; // NVME WRITE
                    sptwb.Spt.Cdb[1] = 0x00; // ADMIN
                    sptwb.Spt.Cdb[2] = 0x00; // 
                    sptwb.Spt.Cdb[3] = 0xfd; // OP Code
                    sptwb.Spt.Cdb[4] = 0x01;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0x60;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0x00;

                    length = (uint)(Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_WITH_BUFFERS_DIRECT), "DataBuf").ToInt32() + sptwb.Spt.DataTransferLength);

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    if (bRet == false)
                    {
                        bRet = false;
                        return bRet;
                    }

                    //============== 第一階段  End ====================================

                    //============== 第二階段  Start ====================================
                    sptwb.Spt.CdbLength = 16;
                    sptwb.Spt.Cdb[0] = 0xE5; // NVME WRITE
                    sptwb.Spt.Cdb[1] = 0x00; // ADMIN
                    sptwb.Spt.Cdb[2] = 0x00; // 
                    sptwb.Spt.Cdb[3] = 0x80; // OP Code
                    sptwb.Spt.Cdb[4] = 0;
                    sptwb.Spt.Cdb[5] = 0;
                    sptwb.Spt.Cdb[6] = 0;
                    sptwb.Spt.Cdb[7] = 0;
                    sptwb.Spt.Cdb[8] = 0;
                    sptwb.Spt.Cdb[9] = 0;
                    sptwb.Spt.Cdb[10] = 0;
                    sptwb.Spt.Cdb[11] = 0;

                    Marshal.StructureToPtr(sptwb, inpBuffer, true);

                    bRet = DeviceIoControl(hIoCtrl, IOCTL_SCSI_PASS_THROUGH, inpBuffer, length, inpBuffer, length, ref dwReturned, IntPtr.Zero);

                    //============== 第二階段  End ====================================

                    if (bRet == true)
                    {
                        Console.WriteLine("成功格式化");
                    }

                }
                catch (Exception ex)
                {
                    Track.WriteLine(ex.ToString());
                    bRet = false;
                    return bRet;
                }
                finally
                {
                    if (inpBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(inpBuffer);
                        inpBuffer = IntPtr.Zero;
                    }

                    if (hIoCtrl != null)
                    {
                        hIoCtrl.Close();
                    }
                }

                return bRet;
            }
            #endregion
        }
        #endregion

    }

    /// <summary>
    /// 映射 BridgeName，決定採用的 Command型態
    /// </summary>
    public static class BridgeControlName_MappingCommands
    {
        private static string BridgeControl_Name = @"";

        /// <summary>
        /// 為了解決"循環相依問題:，只好透過外部再把資料取回。
        /// </summary>
        public static void SetLocal_BridgeControl_Name(string aControl_Name)
        {
            if (!String.IsNullOrEmpty(aControl_Name))
            {
                BridgeControlName_MappingCommands.BridgeControl_Name = aControl_Name;
            }
            else
            {
                BridgeControlName_MappingCommands.BridgeControl_Name = @"";
            }

        }

        public static ExternBase.COMMAND_TYPE GetCommandType()
        {
            ExternBase.COMMAND_TYPE aType = ExternBase.COMMAND_TYPE.CMD_TYPE_UNKNOWN;

            if (!String.IsNullOrEmpty(BridgeControlName_MappingCommands.BridgeControl_Name))
            {
                #region SATA
                if (BridgeControlName_MappingCommands.BridgeControl_Name.Contains(@"JMS580"))
                {
                    aType = ExternBase.COMMAND_TYPE.CMD_TYPE_SAT;
                }

                if (BridgeControlName_MappingCommands.BridgeControl_Name.Contains(@"ASM235"))
                {
                    aType = ExternBase.COMMAND_TYPE.CMD_TYPE_SAT;
                }
                #endregion

                #region PCIE
                if (BridgeControlName_MappingCommands.BridgeControl_Name.Contains(@"ASM2362"))
                {
                    aType = ExternBase.COMMAND_TYPE.CMD_TYPE_NVME_ASMEDIA;
                }

                if (BridgeControlName_MappingCommands.BridgeControl_Name.Contains(@"RTL9210"))
                {
                    aType = ExternBase.COMMAND_TYPE.CMD_TYPE_NVME_REALTEK;
                }

                if (BridgeControlName_MappingCommands.BridgeControl_Name.Contains(@"JMS583"))
                {
                    aType = ExternBase.COMMAND_TYPE.CMD_TYPE_NVME_JMICRON;
                }
                #endregion
            }

            return aType;
        }
    }
}

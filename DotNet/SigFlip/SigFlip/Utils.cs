using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SigFlip
{
    public class Utils
    {

        public static string sha1(byte[] data)
        {
            using (var sha1 = new System.Security.Cryptography.SHA1CryptoServiceProvider())
            {
                return string.Concat(sha1.ComputeHash(data).Select(x => x.ToString("X2")));
            }
        }

        public static void checkSig(string _pePath)
        {
            string _errMsg = "";
            bool isValid = _WinVerifyTrust.checkSig(_pePath, out _errMsg);

            if (isValid)
            {
                Console.WriteLine("[*]:" + _pePath + @" has a valid signature");
            }
            else
            {
                Console.WriteLine("[!]:" + _pePath + @" signature is NOT valid");
            }
        }

        public static int scanPattern(byte[] peBytes, byte[] pattern)
        {
            int _max = peBytes.Length - pattern.Length + 1;
            int j;
            for (int i = 0; i < _max; i++)
            {
                if (peBytes[i] != pattern[0]) continue;

                for (j = pattern.Length - 1; j >= 1 && peBytes[i + j] == pattern[j]; j--) ;
                if (j == 0) return i;
            }
            return -1;
        }

        public static bool checkConfig() {

            string _pCheck = "";
            using (RegistryKey _hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            {
                using (RegistryKey regKey = _hklm.OpenSubKey(@"\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"))
                {
                    if (regKey != null)
                    {
                        _pCheck = (string)regKey.GetValue("EnableCertPaddingCheck");
                        if (_pCheck != null) return true;
                    }
                }
            }

            using (RegistryKey _hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
            {
                using (RegistryKey regKey = _hklm.OpenSubKey(@"\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"))
                {
                    if (regKey != null)
                    {
                        _pCheck = (string)regKey.GetValue("EnableCertPaddingCheck");
                        if (_pCheck != null) return true;
                    }
                }
            }

            return false;

        }

        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            T theStructure;
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            }
            finally
            {
                handle.Free();
            }
            return theStructure;
        }

        public static bool Is32Bit(ushort Characteristics)
        {

            UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
            return (IMAGE_FILE_32BIT_MACHINE & Characteristics) == IMAGE_FILE_32BIT_MACHINE;
        }
        public static void WriteFile(string filename, byte[] rawData)
        {
            FileStream fs = new FileStream(filename, FileMode.OpenOrCreate);
            fs.Write(rawData, 0, rawData.Length);
            fs.Close();
        }

        public static byte[] Read(string filePath)
        {
            using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                byte[] rawData = new byte[stream.Length];
                stream.Read(rawData, 0, (int)stream.Length);
                stream.Close();

                return rawData;
            }
        }

        public static void MMarshal<T>(int _structLength, T _struct, uint _offset, byte[] pe)
        {
            byte[] _structBytes = new byte[_structLength];

            Array.Copy(RawMarshal(_struct), 0, pe, _offset, Marshal.SizeOf(typeof(T)));

        }

        public static byte[] RawMarshal(object anything)
        {
            int rawsize = Marshal.SizeOf(anything);
            byte[] rawdata = new byte[rawsize];
            GCHandle handle = GCHandle.Alloc(rawdata, GCHandleType.Pinned);
            Marshal.StructureToPtr(anything, handle.AddrOfPinnedObject(), false);
            handle.Free();

            return rawdata;
        }

        public static string GenRandomBytes(int size, bool lowerCase = false)
        {
            Random _random = new Random();
            var builder = new StringBuilder(size);

            char offset = lowerCase ? 'a' : 'A';
            const int lettersOffset = 26;

            for (var i = 0; i < size; i++) {
                var @char = (char)_random.Next(offset, offset + lettersOffset);
                builder.Append(@char);
            }

            return lowerCase ? builder.ToString().ToLower() : builder.ToString();
        }

       public static byte[] Encrypt(byte[] data, string encKey)
        {
            byte[] T = new byte[256];
            byte[] S = new byte[256];
            int keyLen = encKey.Length;
            int dataLen = data.Length;
            byte[] result = new byte[dataLen];
            byte tmp;
            int j = 0, t = 0, i = 0;


            for (i = 0; i < 256; i++)
            {
                S[i] = Convert.ToByte(i);
                T[i] = Convert.ToByte(encKey[i % keyLen]);
            }

            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                tmp = S[j];
                S[j] = S[i];
                S[i] = tmp;
            }
            j = 0;
            for (int x = 0; x < dataLen; x++)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;

                tmp = S[j];
                S[j] = S[i];
                S[i] = tmp;

                t = (S[i] + S[j]) % 256;

                result[x] = Convert.ToByte(data[x] ^ S[t]);
            }

            return result;
        }


    }

    //stolen from https://www.codeproject.com/Articles/3111/C-NET-Command-Line-Arguments-Parser
    public class ArgumentParser
    {
        private StringDictionary Parameters;

        public ArgumentParser(string[] Args)
        {
            Parameters = new StringDictionary();
            Regex Spliter = new Regex(@"^-{1,2}",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);

            Regex Remover = new Regex(@"^['""]?(.*?)['""]?$",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);

            string Parameter = null;
            string[] Parts;

            foreach (string Txt in Args)
            {
                Parts = Spliter.Split(Txt, 3);

                switch (Parts.Length)
                {
                    case 1:
                        if (Parameter != null)
                        {
                            if (!Parameters.ContainsKey(Parameter))
                            {
                                Parts[0] =
                                    Remover.Replace(Parts[0], "$1");

                                Parameters.Add(Parameter, Parts[0]);
                            }
                            Parameter = null;
                        }

                        break;

                    case 2:

                        if (Parameter != null)
                        {
                            if (!Parameters.ContainsKey(Parameter))
                                Parameters.Add(Parameter, "true");
                        }
                        Parameter = Parts[1];
                        break;

                    case 3:
                        if (Parameter != null)
                        {
                            if (!Parameters.ContainsKey(Parameter))
                                Parameters.Add(Parameter, "true");
                        }

                        Parameter = Parts[1];

                        if (!Parameters.ContainsKey(Parameter))
                        {
                            Parts[2] = Remover.Replace(Parts[2], "$1");
                            Parameters.Add(Parameter, Parts[2]);
                        }

                        Parameter = null;
                        break;
                }
            }
            if (Parameter != null)
            {
                if (!Parameters.ContainsKey(Parameter))
                    Parameters.Add(Parameter, "true");
            }
        }

        public string this[string Param]
        {
            get
            {
                return (Parameters[Param]);
            }
        }

        public string GetOrDefault(string key, string defaultValue)
        {
            if (!Parameters.ContainsKey(key))
            {
                return defaultValue;
            }

            return Parameters[key];
        }
    }
}

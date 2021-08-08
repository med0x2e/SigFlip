using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using static SigFlip.PEHeaders;

namespace SigFlip
{
    public class PE
    {
  
        #region Fields

        public IMAGE_DOS_HEADER dosHeader;
        public IMAGE_FILE_HEADER fileHeader;
        public IMAGE_OPTIONAL_HEADER32 optionalHeader32;
        public IMAGE_OPTIONAL_HEADER64 optionalHeader64;
        public WIN_CERTIFICATE winCert;

        #endregion Fields

        public PE(string filePath)
        {
            using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = Utils.FromBinaryReader<IMAGE_DOS_HEADER>(reader);
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                UInt32 ntHeadersSignature = reader.ReadUInt32();
                fileHeader = Utils.FromBinaryReader<IMAGE_FILE_HEADER>(reader);

                if (Utils.Is32Bit(this.fileHeader.Characteristics))
                {
                    optionalHeader32 = Utils.FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                    stream.Seek(optionalHeader32.CertificateTable.VirtualAddress, SeekOrigin.Begin);
                    winCert = Utils.FromBinaryReader<WIN_CERTIFICATE>(reader);
                }
                else
                {
                    optionalHeader64 = Utils.FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                    stream.Seek(optionalHeader64.CertificateTable.VirtualAddress, SeekOrigin.Begin);
                    winCert = Utils.FromBinaryReader<WIN_CERTIFICATE>(reader);
                }

               

            }
        }


    }
}

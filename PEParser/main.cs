using System;
using System.Runtime.InteropServices;
using System.Text;

namespace PEParser
{
    public abstract class APEStructure
    {
        protected IPeParser PeParser;
        protected int Offset;
        protected APEStructure(IPeParser peParser, int offset)
        {
            PeParser = peParser;
            Offset = offset;
        }
    }
    public class PEFile
    {
        #region 辅助字段
        protected bool _isPE64;
        protected bool _isPE32;
        #endregion


        #region PE Header - Pe 头部
        public ImageDosHeader ImageDosHeader => PeParser.GetImageDosHeader();
        public ImageNtHeader ImageNtHeader => PeParser.GetImageNtHeader();
        public ImageSectionHeader[] ImageSectionHeaders => PeParser.GetImageSectionHeaders();
        #endregion


        #region 构造函数
        public PEFile(string filePath)
            : this(System.IO.File.ReadAllBytes(filePath))
        {

        }
        public PEFile(IPeParser peParser)
        {
            PeParser = peParser;
        }
        public PEFile(byte[] buffer)
            : this(new RawPeParser(buffer))
        {

        }
        #endregion


        #region PE 解析器
        private IPeParser PeParser;
        #endregion

    }
    public interface IPeParser
    {
        #region 提供读写操作
        byte[] Read(int offset, int size);
        byte ReadByte(int offset);
        ushort ReadWord(int offset);
        uint ReadDword(int offset);
        ulong ReadQword(int offset);
        public string ReadAsciiString(int offset, int size = 0);

        void Write(byte[] data, int offset, int size);
        void WriteByte(byte data, int offset);
        void WriteWord(ushort data, int offset);
        void WriteDword(uint data, int offset);
        void WriteQword(ulong data, int offset);
        //void WriteAsciiString(string data, int offset);
        #endregion


        #region PE 结构体解析
        ImageDosHeader GetImageDosHeader();
        ImageNtHeader GetImageNtHeader();
        ImageFileHeader GetImageFileHeader();
        ImageOptionalHeader GetImageOptionalHeader();
        ImageSectionHeader[] GetImageSectionHeaders();
        ImageDataDirectory[] GetImageDataDirectories();
        #endregion


        #region 辅助函数
        bool IsPe32 { get; }
        bool IsPe64 { get; }
        #endregion
    }

    public class RawPeParser : IPeParser
    {
        Memory<byte> _buffer;


        public RawPeParser(byte[] buffer) => _buffer = buffer;


        #region IPeParser 接口实现
        public ImageDosHeader GetImageDosHeader() => new ImageDosHeader(this, 0);
        public ImageNtHeader GetImageNtHeader() => new ImageNtHeader(this, (int)ReadDword(0x3c));
        public ImageFileHeader GetImageFileHeader() => new ImageFileHeader(this, (int)ReadDword(0x3c) + 0x4);
        public ImageOptionalHeader GetImageOptionalHeader() => new ImageOptionalHeader(this, (int)ReadDword(0x3c) + 0x18);
        public ImageSectionHeader[] GetImageSectionHeaders()
        {
            var fileHeader = GetImageFileHeader();
            int off = fileHeader.SizeOfOptionalHeader + (int)ReadDword(0x3c) + 0x18;
            int numberOfSections = fileHeader.NumberOfSections;

            ImageSectionHeader[] imageSections = new ImageSectionHeader[numberOfSections];
            for (int i = 0; i < numberOfSections; i++)
            {
                imageSections[i] = new ImageSectionHeader(this, off + i * 40);
            }

            return imageSections;
        }
        public ImageDataDirectory[] GetImageDataDirectories()
        {
            int off = (int)ReadDword(0x3c) + 0x18;
            off += IsPe32 ? 96 : 112;
            int numberOfdirectories = (int)ReadDword(off - 4);
            ImageDataDirectory[] directories = new ImageDataDirectory[numberOfdirectories];
            for (int i = 0; i < numberOfdirectories; i++)
            {
                directories[i] = new ImageDataDirectory(this, off + i * 8, i);
            }
            return directories;
        }

        public byte[] Read(int offset, int size) => _buffer.Slice(offset, size).ToArray();
        public byte ReadByte(int offset) => _buffer.Span[offset];
        public uint ReadDword(int offset) => MemoryMarshal.Read<uint>(_buffer.Span[offset..]);
        public ulong ReadQword(int offset) => MemoryMarshal.Read<ulong>(_buffer.Span[offset..]);
        public ushort ReadWord(int offset) => MemoryMarshal.Read<ushort>(_buffer.Span[offset..]);
        public string ReadAsciiString(int offset, int size)
        {
            byte value = 0;
            Span<byte> span = _buffer.Span;
            int length = span[new Range(start: offset, end: _buffer.Length)].IndexOf(value);
            return Encoding.ASCII.GetString(_buffer.Span.Slice(offset, length <= size || size == 0 ? length : size));
        }

        public void Write(byte[] data, int offset, int size) => data[new Range(0, size)].CopyTo(_buffer.Span[offset..]);
        public void WriteByte(byte data, int offset) => _buffer.Span[offset] = data;
        public void WriteDword(uint data, int offset) => MemoryMarshal.Write<uint>(_buffer.Span[offset..], ref data);
        public void WriteQword(ulong data, int offset) => MemoryMarshal.Write<ulong>(_buffer.Span[offset..], ref data);
        public void WriteWord(ushort data, int offset) => MemoryMarshal.Write<ushort>(_buffer.Span[offset..], ref data);
        #endregion


        #region 辅助函数
        public bool IsPe64 => ReadWord((int)ReadDword(0x3c) + 0x18) == 0x20B;
        public bool IsPe32 => ReadWord((int)ReadDword(0x3c) + 0x18) == 0x10B;
        #endregion 

    }

    public class ImageDosHeader : APEStructure
    {
        public ImageDosHeader(IPeParser peParser, int offset)
            : base(peParser, offset)
        {

        }

        public ushort E_magic
        {
            get
            {
                return PeParser.ReadWord(Offset + 0);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 0);
            }
        }
        public ushort E_cblp
        {
            get
            {
                return PeParser.ReadWord(Offset + 2);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 2);
            }
        }
        public ushort E_cp
        {
            get
            {
                return PeParser.ReadWord(Offset + 4);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 4);
            }
        }
        public ushort E_crlc
        {
            get
            {
                return PeParser.ReadWord(Offset + 6);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 6);
            }
        }
        public ushort E_cparhdr
        {
            get
            {
                return PeParser.ReadWord(Offset + 8);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 8);
            }
        }
        public ushort E_minalloc
        {
            get
            {
                return PeParser.ReadWord(Offset + 10);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 10);
            }
        }
        public ushort E_maxalloc
        {
            get
            {
                return PeParser.ReadWord(Offset + 12);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 12);
            }
        }
        public ushort E_ss
        {
            get
            {
                return PeParser.ReadWord(Offset + 14);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 14);
            }
        }
        public ushort E_sp
        {
            get
            {
                return PeParser.ReadWord(Offset + 16);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 16);
            }
        }
        public ushort E_csum
        {
            get
            {
                return PeParser.ReadWord(Offset + 18);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 18);
            }
        }
        public ushort E_ip
        {
            get
            {
                return PeParser.ReadWord(Offset + 20);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 20);
            }
        }
        public ushort E_cs
        {
            get
            {
                return PeParser.ReadWord(Offset + 22);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 22);
            }
        }
        public ushort E_lfarlc
        {
            get
            {
                return PeParser.ReadWord(Offset + 24);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 24);
            }
        }
        public ushort E_ovno
        {
            get
            {
                return PeParser.ReadWord(Offset + 26);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 26);
            }
        }
        public ushort[] E_res
        {
            get
            {
                return new ushort[]
                {
                    PeParser.ReadWord(Offset+28),
                    PeParser.ReadWord(Offset+30),
                    PeParser.ReadWord(Offset+32),
                    PeParser.ReadWord(Offset+34),
                };
            }
            set
            {
                PeParser.WriteWord(value[0], Offset + 28);
                PeParser.WriteWord(value[1], Offset + 30);
                PeParser.WriteWord(value[2], Offset + 32);
                PeParser.WriteWord(value[3], Offset + 34);
            }
        }
        public ushort E_oemid
        {
            get
            {
                return PeParser.ReadWord(Offset + 36);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 36);
            }
        }
        public ushort E_oeminfo
        {
            get
            {
                return PeParser.ReadWord(Offset + 38);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 38);
            }
        }
        public ushort[] E_res2
        {
            get
            {
                ushort[] res2 = new ushort[10];
                for (int i = 0; i < 10; i++)
                {
                    res2[i] = PeParser.ReadWord(Offset + 40 + i * 2);
                }
                return res2;
            }
            set
            {
                for (int i = 0; i < 10; i++)
                {
                    PeParser.WriteWord(value[i], Offset + 40 + i * 2);
                }
            }
        }
        public uint E_lfanew
        {
            get
            {
                return PeParser.ReadDword(Offset + 0x3c);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 0x3c);
            }
        }
    }

    public class ImageNtHeader : APEStructure
    {
        public ImageNtHeader(IPeParser peParser, int offset)
            : base(peParser, offset)
        {

        }
        public uint Signature
        {
            get
            {
                return PeParser.ReadDword(Offset + 0);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 0);
            }
        }
        public ImageFileHeader FileHeader => PeParser.GetImageFileHeader();
        public ImageOptionalHeader OptionalHeader => PeParser.GetImageOptionalHeader();

    }

    public class ImageFileHeader : APEStructure
    {
        public ImageFileHeader(IPeParser peParser, int offset)
            : base(peParser, offset)
        {

        }
        public ushort Machine
        {
            get
            {
                return PeParser.ReadWord(Offset + 0);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 0);
            }
        }
        public ushort NumberOfSections
        {
            get
            {
                return PeParser.ReadWord(Offset + 2);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 2);
            }
        }
        public uint TimeDateStamp
        {
            get
            {
                return PeParser.ReadDword(Offset + 4);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 4);
            }
        }
        public uint PointerToSymbolTable
        {
            get
            {
                return PeParser.ReadDword(Offset + 8);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 8);
            }
        }
        public uint NumberOfSymbols
        {
            get
            {
                return PeParser.ReadDword(Offset + 12);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 12);
            }
        }
        public ushort SizeOfOptionalHeader
        {
            get
            {
                return PeParser.ReadWord(Offset + 16);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 16);
            }
        }
        public ushort Characteristics
        {
            get
            {
                return PeParser.ReadWord(Offset + 18);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 18);
            }
        }
    }

    public class ImageOptionalHeader : APEStructure
    {
        public ImageOptionalHeader(IPeParser peParser, int offset)
            : base(peParser, offset)
        {
            DataDirectory = PeParser.GetImageDataDirectories();
        }

        public ushort Magic
        {
            get
            {
                return PeParser.ReadWord(Offset);
            }
            set
            {
                PeParser.WriteWord(value, Offset);
            }
        }
        public byte MajorLinkerVersion
        {
            get
            {
                return PeParser.ReadByte(Offset + 2);
            }
            set
            {
                PeParser.WriteByte(value, Offset + 2);
            }
        }
        public byte MinorLinkerVersion
        {
            get
            {
                return PeParser.ReadByte(Offset + 3);
            }
            set
            {
                PeParser.WriteByte(value, Offset + 3);
            }
        }
        public uint SizeOfCode
        {
            get
            {
                return PeParser.ReadDword(Offset + 4);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 4);
            }
        }
        public uint SizeOfInitializedData
        {
            get
            {
                return PeParser.ReadDword(Offset + 8);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 8);
            }
        }
        public uint SizeOfUninitializedData
        {
            get
            {
                return PeParser.ReadDword(Offset + 12);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 12);
            }
        }
        public uint AddressOfEntryPoint
        {
            get
            {
                return PeParser.ReadDword(Offset + 16);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 16);
            }
        }
        public uint BaseOfCode
        {
            get
            {
                return PeParser.ReadDword(Offset + 20);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 20);
            }
        }
        public uint BaseOfData //only PE32
        {
            get
            {
                return PeParser.IsPe32 ? PeParser.ReadDword(Offset + 24) : 0;
            }
            set
            {

                if (PeParser.IsPe32) PeParser.WriteDword(value, Offset + 24);
            }
        }
        public ulong ImageBase
        {
            get
            {
                return PeParser.IsPe32 ? PeParser.ReadDword(Offset + 28) : PeParser.ReadQword(Offset + 24);
            }
            set
            {
                if (PeParser.IsPe32) PeParser.WriteDword((uint)value, Offset + 28);
                else if (PeParser.IsPe64) PeParser.WriteQword(value, Offset + 24);
            }
        }
        public uint SectionAlignment
        {
            get
            {
                return PeParser.ReadDword(Offset + 32);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 32);
            }
        }
        public uint FileAlignment
        {
            get
            {
                return PeParser.ReadDword(Offset + 36);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 36);
            }
        }
        public ushort MajorOperatingSystemVersion
        {
            get
            {
                return PeParser.ReadWord(Offset + 40);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 40);
            }
        }
        public ushort MinorOperatingSystemVersion
        {
            get
            {
                return PeParser.ReadWord(Offset + 42);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 42);
            }
        }
        public ushort MajorImageVersion
        {
            get
            {
                return PeParser.ReadWord(Offset + 44);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 44);
            }
        }
        public ushort MinorImageVersion
        {
            get
            {
                return PeParser.ReadWord(Offset + 46);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 46);
            }
        }
        public ushort MajorSubsystemVersion
        {
            get
            {
                return PeParser.ReadWord(Offset + 48);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 48);
            }
        }
        public ushort MinorSubsystemVersion
        {
            get
            {
                return PeParser.ReadWord(Offset + 50);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 50);
            }
        }
        public uint Win32VersionValue
        {
            get
            {
                return PeParser.ReadDword(Offset + 52);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 52);
            }
        }
        public uint SizeOfImage
        {
            get
            {
                return PeParser.ReadDword(Offset + 56);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 56);
            }
        }
        public uint SizeOfHeaders
        {
            get
            {
                return PeParser.ReadDword(Offset + 60);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 60);
            }
        }
        public uint CheckSum
        {
            get
            {
                return PeParser.ReadDword(Offset + 64);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 64);
            }
        }
        public ushort Subsystem
        {
            get
            {
                return PeParser.ReadWord(Offset + 68);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 68);
            }
        }
        public ushort DllCharacteristics
        {
            get
            {
                return PeParser.ReadWord(Offset + 70);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 70);
            }
        }
        public ulong SizeOfStackReserve
        {
            get
            {
                return PeParser.IsPe32 ? PeParser.ReadDword(Offset + 72) : PeParser.ReadQword(Offset + 72);
            }
            set
            {
                if (PeParser.IsPe32) PeParser.WriteDword((uint)value, Offset + 72);
                else PeParser.WriteQword(value, Offset + 72);
            }
        }
        public ulong SizeOfStackCommit
        {
            get
            {
                return PeParser.IsPe32 ? PeParser.ReadDword(Offset + 76) : PeParser.ReadQword(Offset + 80);
            }
            set
            {
                if (PeParser.IsPe32) PeParser.WriteDword((uint)value, Offset + 76);
                else PeParser.WriteQword(value, Offset + 80);
            }
        }
        public ulong SizeOfHeapReserve
        {
            get
            {
                return PeParser.IsPe32 ? PeParser.ReadDword(Offset + 80) : PeParser.ReadQword(Offset + 88);
            }
            set
            {
                if (PeParser.IsPe32) PeParser.WriteDword((uint)value, Offset + 80);
                else PeParser.WriteQword(value, Offset + 88);
            }
        }
        public ulong SizeOfHeapCommit
        {
            get
            {
                return PeParser.IsPe32 ? PeParser.ReadDword(Offset + 84) : PeParser.ReadQword(Offset + 96);
            }
            set
            {
                if (PeParser.IsPe32) PeParser.WriteDword((uint)value, Offset + 84);
                else PeParser.WriteQword(value, Offset + 96);
            }
        }
        public uint LoaderFlags
        {
            get
            {
                return PeParser.IsPe32 ? PeParser.ReadDword(Offset + 88) : PeParser.ReadDword(Offset + 104);
            }
            set
            {
                if (PeParser.IsPe32) PeParser.WriteDword(value, Offset + 88);
                else PeParser.WriteDword(value, Offset + 104);
            }
        }
        public uint NumberOfRvaAndSizes
        {
            get
            {
                return PeParser.IsPe32 ? PeParser.ReadDword(Offset + 92) : PeParser.ReadDword(Offset + 108);
            }
            set
            {
                if (PeParser.IsPe32) PeParser.WriteDword(value, Offset + 92);
                else PeParser.WriteDword(value, Offset + 108);
            }
        }
        public readonly ImageDataDirectory[] DataDirectory;

    }

    public class ImageSectionHeader : APEStructure
    {
        public ImageSectionHeader(IPeParser peParser, int offset)
            : base(peParser, offset)
        {

        }
        //public ulong ImageBaseAddress;
        public string Name
        {
            get
            {
                return PeParser.ReadAsciiString(Offset, 8);
            }
            set
            {
                PeParser.Write(Encoding.ASCII.GetBytes(value), Offset, 8);
            }
        }
        public uint VirtualSize
        {
            get
            {
                return PeParser.ReadDword(Offset + 8);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 8);
            }
        }
        public uint VirtualAddress
        {
            get
            {
                return PeParser.ReadDword(Offset + 12);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 12);
            }
        }
        public uint SizeOfRawData
        {
            get
            {
                return PeParser.ReadDword(Offset + 16);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 16);
            }
        }
        public uint PointerToRawData
        {
            get
            {
                return PeParser.ReadDword(Offset + 20);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 20);
            }
        }
        public uint PointerToRelocations
        {
            get
            {
                return PeParser.ReadDword(Offset + 24);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 24);
            }
        }
        public uint PointerToLinenumbers
        {
            get
            {
                return PeParser.ReadDword(Offset + 28);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 28);
            }
        }
        public ushort NumberOfRelocations
        {
            get
            {
                return PeParser.ReadWord(Offset + 32);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 32);
            }
        }
        public ushort NumberOfLinenumbers
        {
            get
            {
                return PeParser.ReadWord(Offset + 34);
            }
            set
            {
                PeParser.WriteWord(value, Offset + 34);
            }
        }
        public uint Characteristics
        {
            get
            {
                return PeParser.ReadDword(Offset + 36);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 36);
            }
        }

    }

    public class ImageDataDirectory : APEStructure
    {
        public ImageDataDirectory(IPeParser peParser, int offset, int number)
            : base(peParser, offset)
        {
            DataName = number switch
            {
                0 => "Export Table Directory",
                1 => "Import Table Directory",
                2 => "Resource Table Directory",
                3 => "Exception Table Directory",
                4 => "Certificate Table Directory",
                5 => "Base Relocation Table Directory",
                6 => "Debug Directory",
                7 => "Architecture Directory",
                8 => "Global Ptr Directory(Reserved)",
                9 => "TLS Table Directory",
                10 => "Configuration table Directory",
                11 => "Bound Import Directory",
                12 => "IAT Directory",
                13 => "Delay Import Descriptor",
                14 => "CLR Runtime Header Directory",
                15 => "Reserved",
                _  => "Reserved"
            };
        }
        public string DataName { get; }
        public uint VirtualAddress
        {
            get
            {
                return PeParser.ReadDword(Offset);
            }
            set
            {
                PeParser.WriteDword(value, Offset);
            }
        }
        public uint Size
        {
            get
            {
                return PeParser.ReadDword(Offset + 4);
            }
            set
            {
                PeParser.WriteDword(value, Offset + 4);
            }
        }
    }
}

using System;
using System.Runtime.InteropServices;
using System.Text;
using PEParser;

namespace PE
{
    public class Program
    {
        static void Main(string[] args)
        {

            var pe = new PEFile(@"C:\Users\cxing\Desktop\ctf3.exe");
            //var el = (int)pe.PeParser.ReadDword(0x3c);
            
            
            return;
        }
    }
    

    

}

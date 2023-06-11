using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace MSx70_Flasher
{
    class Checksums_Signatures
    {
        public byte[] GetSecurityAccessMessage(byte[] userID, byte[] serialNumber, byte[] seed)
        {
            BigInteger n = 1; //modulus -- initialized to 1 to avoid a potential divide by 0 scenario -- should be overwritten below regardless
            BigInteger d = 0; //private exponent

            if (Global.HW_Ref == "0049R20") //MSS70
            {
                n = BigInteger.Parse("8217010497678429229943401791603749355846925215942375750258843727037258323774333432291824564430360214786797252479495103649991108486846288119543565027508177"); //modulus
                d = BigInteger.Parse("7043151855152939339951487249946070876440221613664893500221866051746221420377841774672464468823790466059829844480042727836817363328493068037797229849955103"); //private exponent
            }
            if  (Global.HW_Ref == "0049PP0") //MSV70
            {
                n = BigInteger.Parse("8806306843379798992853111245198774700528705475723069265707220991618051039931302477183469869457986639335679139019018788335207607895197742283782592839289633"); //modulus
                d = BigInteger.Parse("3774131504305628139794190533656617728798016632452743971017380424979164731399047585139420836879747609597530237254645640097349845943512098793420096824927003"); //private exponent
            }

            byte[] toHash = userID.Concat(serialNumber.Concat(seed)).ToArray(); //Hash of UserID + Serial Number + Random number = authentication message

            MD5 md5hash = MD5.Create();
            byte[] hash = new byte[16];
            hash = md5hash.ComputeHash(toHash); //generate MD5 

            BigInteger ToEncrypt = new BigInteger(Append0(hash)); //Need to add a leading zero to hash so that we don't run into +/- issues
            BigInteger Encrypted = BigInteger.ModPow(ToEncrypt, d, n); //RSA encrypt the result (message ^ private exponent % modulus)
            byte[] encryptedArray = new Byte[64];
            encryptedArray = Encrypted.ToByteArray(); //Store result in array
            byte[] authPayload = new Byte[65]; //Need to swap endianness
            authPayload[64] = 3;

            for (int i = 0; i < 16; ++i)
            {
                authPayload[0 + 4 * (i)] = encryptedArray[3 + 4 * i];
                authPayload[1 + 4 * (i)] = encryptedArray[2 + 4 * i];
                authPayload[2 + 4 * (i)] = encryptedArray[1 + 4 * i];
                authPayload[3 + 4 * (i)] = encryptedArray[0 + 4 * i];
            }

            byte[] authHeader = { 01, 00, 00, 00, 0x0A, 00, 00, 00, 00, 00, 00, 00, 00, 0x44, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 0x10 }; //Ediabas wants to see this header -- full meaning can be seen in those comments
            byte[] authMessage = authHeader.Concat(authPayload).ToArray();
            return authMessage;
        }

        public byte[] CorrectParameterChecksums(byte[] DataToFlash)
        {

            uint dataInitial = BitConverter.ToUInt32(DataToFlash.Skip(0xA0).Take(4).Reverse().ToArray(), 0);
            //uint mo3Location;

            //DataToFlash = FixMO3CheckSum(DataToFlash, mo3Location, mo3Start, mo3End);
            uint dataCS_calculated = GetChecksum(DataToFlash, 0xA8, dataInitial, 0x840000);

            byte[] dataCS_calc_array = BitConverter.GetBytes(dataCS_calculated);
            Console.WriteLine(dataCS_calculated.ToString("x"));
            for (int i = 0; i < 4; ++i)
                DataToFlash[0xA4 + i] = dataCS_calc_array[3 - i];



            return DataToFlash;
        }

        private byte[] FixMO3CheckSum(byte[] array, uint mo3Location, uint mo3Start, uint mo3End)
        {
            /*Todo - actually write this code. Python example below
                import struct
                import sys

                def CalcMO3CS(binary):
                    CSLocation = 0x48EA8 #Location of checksum
                    cs = ''

                    for i in range (0, 2):
                        binary.seek(CSLocation + 4*i)
                        cs += format(struct.unpack('>L',binary.read(4))[0],'02x').rjust(8,'0') #Reads high/low checksums, returns MSB first
                    print ('Stored CS: ' + cs)

                    binary.seek(0x803B4) #Location of MO3 start pointer
                    start = struct.unpack('>L',binary.read(4))[0] # '>L' = Read as Big Endian Long Unsigned
                    binary.seek(0x803B8) #Location of M03 end pointer
                    end = struct.unpack('>L',binary.read(4))[0] 
                    index = start
                    csCalc = 0x123456789ABCDEF

                    while index < end : 
                        binary.seek(index - 0x800000)
                        csCalc += struct.unpack('>L',binary.read(4))[0]
                        index += 4


                    print ('Calculated CS: ' + format(csCalc,'02x').rjust(16,'0')[8:16] + format(csCalc,'02x').rjust(16,'0')[0:8])


                if len(sys.argv) == 1:
                    if sys.version_info[0] < 3:
                        filename = raw_input("Enter path/filename: ")
                    else:
                        filename = input("Enter path/filename: ")
                    print ("Note: You can also give filename as a command line argument\n")
                else:
                    filename = sys.argv[1]

                data = open(filename,"rb")
                CalcMO3CS(data)

            Issues: 
                The start and end of the checked region can be progmatically determined, but as best as I can tell, the location of the actual checksum does not have an easy to find pointer
                Unfortunately the "A5" bypass that is present in MS45 is broken in MSV70 and later
            Strategies:
                Hardcode checksum locations? Would need to do for each program version or only support certain versions
                Just patch out the check altogether while preparing the program flash? Current RSA defeat strategy would basically force program to be flashed twice the first time around for that to work. 
           
             */
            return array;
        }

        public byte[] PrepareProgram (byte[] external, byte[] mpc, bool bypassRSA)
        {
            /*RSA Defeat discussion:
            With current state of technology, it is not feasible to factor the public key itself (RSA 1024). Therefore have to find flaws in the siganture verification

            Employed strategy is similar to other Siemens DMEs of same vintage. Broad Overview:
                Erase tune, copy unmodified boot loader to 0x40000 (location of tune normally)
                Patch RSA check in new bootloader to be flashed (at 0x60000)
                Copy original checksums etc to empty space
                Modify pointers to look at data you copied above, pad to desired length
                Generated hash should match original if done correctly.
                If check passes, DME will erase active bootloader and copy new patched bootloader from 0x60000. 
                Future RSA checks will always result as passed until a stock bootloader is flashed back (i.e with WinKFP)
                Tune will have been erased, so needs to be flashed back after this procedure
            

            Potential issue: Is the empty space we're using truly empty in all MSV70 / MSS70 variants?   

            Other potential strategies for RSA bypass
                If the signature validation only checks the bottom 16 bytes (i.e length of MD5) or some other padding flaw exists, an attack similar to this may be feasible: https://arxiv.org/pdf/1802.00359.pdf
                Alternatively, is there a flaw that would allow us to write the "check passed" bytes directly like on the MSS65, avoiding the need for a boot sector modification altogether?          
            */

            //Note, this routine will always patch the actual RSA check, so programs will not be flashable without performing the RSA bypass procedure first
            //In theory it should not break other methods to patch the RSA check, but difficult to guarantee, so generally recommend starting from a stock binary if you don't have means to recover a brick


            byte[] boot = external.Skip(0x20000).Take(0x1FF80).ToArray();

            byte[] rsa_check = { 0x81, 0x86, 00, 00, 0x28, 0x0C, 00, 0x20, 0x40, 0x81, 00, 0x0C, 0x38, 0x60, 0xFF, 0xFF };
            byte[] rsa_patch = { 0x81, 0x86, 00, 00, 0x28, 0x0C, 00, 0x00, 0x41, 0x80, 00, 0x0C, 0x38, 0x60, 0x00, 0x00 };

            byte[] boot_patched = boot;


            int indexOfRSASequence = SearchBytes(boot, rsa_check);
            if (indexOfRSASequence != -1)
            {
                for (int i = 0; i < rsa_patch.Length; ++i)
                    boot_patched[indexOfRSASequence + i] = rsa_patch[i];
                Console.WriteLine("RSA Patched @ 0x" + (indexOfRSASequence + 0x20000).ToString("x"));
            }
            else
                Console.WriteLine("Unable to find RSA sequence. Already patched?");
            

            uint bootCS1Initial = BitConverter.ToUInt32(boot.Skip(0x40).Take(0x4).Reverse().ToArray(), 0);
            uint bootCS1_calculated = GetChecksum(boot_patched, 0x48, bootCS1Initial, 0x20000);
            byte[] bootCS1_calc_array = BitConverter.GetBytes(bootCS1_calculated);
            Console.WriteLine(bootCS1_calculated.ToString("x"));
            for (int i = 0; i < 4; ++i)
                boot_patched[0x44 + i] = bootCS1_calc_array[3 - i];

            uint bootCS2Initial = BitConverter.ToUInt32(boot_patched.Skip(0x10).Take(0x4).Reverse().ToArray(), 0);
            uint bootCS2_calculated = GetChecksum(boot_patched, 0x18, bootCS2Initial, 0x60000);
            byte[] bootCS2_calc_array = BitConverter.GetBytes(bootCS2_calculated);
            Console.WriteLine(bootCS2_calculated.ToString("x"));
            for (int i = 0; i < 4; ++i)
                boot_patched[0x14 + i] = bootCS2_calc_array[3 - i];


            byte[] RSA_Pointers  = 
                {
                0x00, 0x00, 0x00, 0x05,//Number of segments

                //Segment Start and End Addreses -- originals in comments
                0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0xFF, 0x7F,//00060000 0007FF7F
                0x00, 0x17, 0xF0, 0x00, 0x00, 0x17, 0xF2, 0xFF,//00080100 0008023F
                0x00, 0x08, 0x05, 0x40, 0x00, 0x17, 0xEF, 0xFF,//00080380 000FFFFF
                0x00, 0x17, 0xE0, 0x00, 0x00, 0x17, 0xEF, 0xFF,//00100000 0017FFFF
                0x00, 0x40, 0x00, 0x00, 0x00, 0x47, 0xFF, 0xFF,//00400000 0047FFFF

                0x00, 0x01, 0xFF, 0x80,//0001FF80
                0x00, 0x00, 0x03, 0x00,//00000140
                0x00, 0x0F, 0xEA, 0xC0,//0007FC80
                0x00, 0x00, 0x10, 0x00,//00080000
                0x00, 0x08, 0x00, 0x00,//00080000
                };

            byte[] OriginalProgramHeader = external.Skip(0x80100).Take(0x140).Concat(external.Skip(0x80380).Take(0x1c0)).ToArray();


            for (int i = 0; i < boot_patched.Length; ++i)
                external[0x60000 + i] = boot_patched[i];

            if (bypassRSA)
            {
                for (int i = 0; i < RSA_Pointers.Length; ++i)
                    external[0x80500 + i] = RSA_Pointers[i];


                for (int i = 0; i < OriginalProgramHeader.Length; ++i)
                    external[0x17F000 + i] = OriginalProgramHeader[i];
            }

            uint ProgramInitial = BitConverter.ToUInt32(external.Skip(0x80100).Take(0x4).Reverse().ToArray(), 0);
            uint ProgramCS_Calculated = GetChecksumProgram(external, mpc, 0x80108, ProgramInitial);
            byte[] ProgramCS_calc_array = BitConverter.GetBytes(ProgramCS_Calculated);
            Console.WriteLine(ProgramCS_Calculated.ToString("x"));
            for (int i = 0; i < 4; ++i)
                external[0x80104 + i] = ProgramCS_calc_array[3 - i];          

            return external;
        }

        private static byte[] Append0(byte[] array) //Array to BigInt function needs a 0 appended to the result to ensure the value is interpreted as positive
        {
            byte[] appended = new byte[array.Length + 1];

            for (int i = 0; i < array.Length; ++i)
                appended[i] = array[i];

            return appended;
        }

        private uint GetChecksum(byte[] binary, uint checkSumSegmentNumberPointer, uint initialValue, uint MemSubtract)
        {
            uint numberOfSegments = BitConverter.ToUInt32(binary.Skip((int)checkSumSegmentNumberPointer).Take(4).Reverse().ToArray(), 0);
            uint checksumStart = 0;
            uint checksumEnd = 0;
            uint initial = initialValue;

            for (int i = 0; i < numberOfSegments; ++i)
            {
                checksumStart = BitConverter.ToUInt32(binary.Skip((int)checkSumSegmentNumberPointer + 4 + (8 * i)).Take(4).Reverse().ToArray(), 0) - MemSubtract;
                checksumEnd = BitConverter.ToUInt32(binary.Skip((int)checkSumSegmentNumberPointer + 8 + (8 * i)).Take(4).Reverse().ToArray(), 0) - MemSubtract;

                initial = Crc32(binary.Skip((int)checksumStart).Take((int)(checksumEnd - checksumStart) + 1).ToArray(), initial);
            }
            Console.WriteLine(initial);
            return initial;
        }

        private uint GetChecksumProgram(byte[] external, byte[] mpc, uint checkSumSegmentNumberPointer, uint initialValue)
        {
            uint numberOfSegments = BitConverter.ToUInt32(external.Skip((int)checkSumSegmentNumberPointer).Take(4).Reverse().ToArray(), 0);
            uint checksumStart = 0;
            uint checksumEnd = 0;
            uint initial = initialValue;

            for (int i = 0; i < numberOfSegments; ++i)
            {
                checksumStart = BitConverter.ToUInt32(external.Skip((int)checkSumSegmentNumberPointer + 4 + (8 * i)).Take(4).Reverse().ToArray(), 0);
                checksumEnd = BitConverter.ToUInt32(external.Skip((int)checkSumSegmentNumberPointer + 8 + (8 * i)).Take(4).Reverse().ToArray(), 0);

                if (checksumStart >= 0x400000)
                {
                    checksumStart -= 0x400000;
                    checksumEnd -= 0x400000;

                    initial = Crc32(mpc.Skip((int)checksumStart).Take((int)(checksumEnd - checksumStart) + 1).ToArray(), initial);
                }
                else
                {
                    initial = Crc32(external.Skip((int)checksumStart).Take((int)(checksumEnd - checksumStart) + 1).ToArray(), initial);
                }
                Console.WriteLine(checksumStart.ToString("x"));
                Console.WriteLine(checksumEnd.ToString("x"));
            }

            return initial;
        }

        private uint Crc32(byte[] buffer, uint initial)
        {
            uint[] table =
            {
                0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
                0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
                0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
                0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
                0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
                0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
                0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
                0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
                0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
                0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
                0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
                0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
                0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
                0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
                0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
                0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
                0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
                0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
                0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
                0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
                0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
                0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
                0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
                0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
                0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
                0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
                0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
                0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
                0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
                0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
                0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
                0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
                0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
                0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
                0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
                0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
                0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
                0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
                0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
                0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
                0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
                0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
                0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
                0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
                0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
                0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
                0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
                0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
                0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
                0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
                0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
                0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
                0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
                0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
                0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
                0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
                0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
                0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
                0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
                0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
                0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
                0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
                0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
                0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4,
        };

            {
                uint crc = initial;
                for (int i = 0; i < buffer.Length; ++i)
                    crc = ((crc << 8) & 0xffffff00) ^ table[(((crc >> 24) & 0xFF) ^ buffer[i])];

                return crc;
            }
        }

        static int SearchBytes(byte[] haystack, byte[] needle)
        {
            var len = needle.Length;
            var limit = haystack.Length - len;
            for (var i = 0; i <= limit; i++)
            {
                var k = 0;
                for (; k < len; k++)
                {
                    if (needle[k] != haystack[i + k]) break;
                }
                if (k == len) return i;
            }
            return -1;
        }
    }
}

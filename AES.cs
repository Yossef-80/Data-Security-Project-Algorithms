using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            string k = key.Substring(2, key.Length - 2);
            k = k.ToUpper();
            string c = cipherText.Substring(2, key.Length - 2);
            c = c.ToUpper();
            string[] keys = generate_keys(k);
            Array.Reverse(keys);

            //round 0
            string[,] cipher_arr = constants.key_string_to_arr(c);
            int[,] cipher_int = constants.hex_to_dec(cipher_arr);
            string[,] key_arr = constants.key_string_to_arr(keys[0]);
            int[,] key_int = constants.hex_to_dec(key_arr);

            int[,] xored_int = AddRoundKey(cipher_int, key_int);
            int[,] inv_shifted = Inverse_Shift_Row(xored_int);
            string[,] inv_subbed = sub_bytes_2d(inv_shifted, constants.get_inverse_s_box());
            int[,] inv_subbed_int = constants.hex_to_dec(inv_subbed);

            //round 1....9
            string[,] hexa_initial_round = constants.dec_to_hex(inv_subbed_int);
            string round0 = constants.arr_to_string(hexa_initial_round);

            string result;

            for (int i = 1; i < 10; i++)
            {
                result = decryption_rounds(round0, keys[i]);
                round0 = result;
            }

            //last round
            result = dec_last_round(round0, keys[10]);
            result = "0x" + result;

            return result;
        }

        public override string Encrypt(string plainText, string key)
        {
            string k = key.Substring(2, key.Length - 2);
            k = k.ToUpper();
            string p = plainText.Substring(2, key.Length - 2);
            p = p.ToUpper();
            string[] keys = generate_keys(k);

            //round 0
            string[,] plain_arr = constants.key_string_to_arr(p);
            int[,] plain_int = constants.hex_to_dec(plain_arr);
            string[,] key_arr = constants.key_string_to_arr(keys[0]);
            int[,] key_int = constants.hex_to_dec(key_arr);
            int[,] initial_round = AddRoundKey(plain_int, key_int);

            //round 1....9
            string[,] hexa_initial_round = constants.dec_to_hex(initial_round);
            string round0 = constants.arr_to_string(hexa_initial_round);

            string result = "";

            for (int i = 1; i < 10; i++)
            {
                result = generate_rounds(round0, keys[i]);
                round0 = result;
            }

            //last round
            result = last_round(round0, keys[10]);
            result = "0x" + result;

            return result;
        }
        public static string generate_rounds(string plain_text, string key)
        {
            string[,] round_plain = constants.string_to_arr(plain_text);
            int[,] round_plain_int = constants.hex_to_dec(round_plain);

            string[,] subbed_round1 = sub_bytes_2d(round_plain_int, constants.get_s_box());
            int[,] subbed_int = constants.hex_to_dec(subbed_round1);
            int[,] shifted_int = ShiftRows(subbed_int);

            int[,] mixed_int = mix_columns(shifted_int, constants.mix_columns_matrix());

            string[,] key1_arr = constants.key_string_to_arr(key);
            int[,] key1_int = constants.hex_to_dec(key1_arr);
            int[,] round1 = AddRoundKey(mixed_int, key1_int);
            string[,] res = constants.dec_to_hex(round1);
            string result = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += (res[i, j]);
                }
            }
            Console.WriteLine(result);
            return result;
        }
        public static string last_round(string plain_text, string key)
        {
            string[,] round_plain = constants.string_to_arr(plain_text);
            int[,] round_plain_int = constants.hex_to_dec(round_plain);

            string[,] subbed_round1 = sub_bytes_2d(round_plain_int, constants.get_s_box());
            int[,] subbed_int = constants.hex_to_dec(subbed_round1);
            int[,] shifted_int = ShiftRows(subbed_int);


            string[,] key1_arr = constants.key_string_to_arr(key);
            int[,] key1_int = constants.hex_to_dec(key1_arr);
            int[,] round1 = AddRoundKey(shifted_int, key1_int);
            string[,] res = constants.dec_to_hex(round1);
            string result = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += (res[j, i]);
                }
            }
            return result;
        }

   
        public static string decryption_rounds(string cipher_text, string key)
        {
            string[,] round_cipher = constants.string_to_arr(cipher_text);
            int[,] round_cipher_int = constants.hex_to_dec(round_cipher);
            string[,] key1_arr = constants.key_string_to_arr(key);
            int[,] key1_int = constants.hex_to_dec(key1_arr);

            int[,] round1 = AddRoundKey(round_cipher_int, key1_int);

            int[,] mixed_int = inverse_mix_columns(round1);

            int[,] inv_shifted_int = Inverse_Shift_Row(mixed_int);

            string[,] inv_subbed = sub_bytes_2d(inv_shifted_int, constants.get_inverse_s_box());
            int[,] inv_subbed_int = constants.hex_to_dec(inv_subbed);

            string[,] res = constants.dec_to_hex(inv_subbed_int);
            string result = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += (res[i, j]);
                }
            }
            //Console.WriteLine(result);
            return result;
        }
        public static int[,] Inverse_Shift_Row(int[,] mat)//matrix 4*4
        {

            int[,] newMat = new int[,]{
                {mat[0,0],mat[0,1],mat[0,2],mat[0,3] },
                {mat[1,3],mat[1,0],mat[1,1],mat[1,2] },
                {mat[2,2],mat[2,3],mat[2,0],mat[2,1] },
                {mat[3,1],mat[3,2],mat[3,3],mat[3,0] },
            };

            return newMat;
        }
        public static int[,] inverse_mix_columns(int[,] text_block)
        {
            //assuming text_block, and matrix are converted to decimal,
            //2 dimensional arrays of size 4*4
            int[,] matrix = constants.inverse_mix_columns_matrix();
            int[,] result = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < 4; k++)
                    {
                        int temp = matrix[i, k];
                        if (temp == 9)
                        {
                            temp = constants.hex_to_dec(    // convert result from string to decimal
                                constants.galois_multiply_by_9(text_block[k, j]).   // get multiplication result via loockup table
                                Substring(2, 2));    // remove 0x
                        }
                        else if (temp == 11)
                        {
                            temp = constants.hex_to_dec(    // convert result from string to decimal
                                constants.galois_multiply_by_11(text_block[k, j]).   // get multiplication result via loockup table
                                Substring(2, 2));    // remove 0x
                        }
                        else if (temp == 13)
                        {
                            temp = constants.hex_to_dec(    // convert result from string to decimal
                                constants.galois_multiply_by_13(text_block[k, j]).   // get multiplication result via loockup table
                                Substring(2, 2));    // remove 0x
                        }
                        else if (temp == 14)
                        {
                            temp = constants.hex_to_dec(    // convert result from string to decimal
                                constants.galois_multiply_by_14(text_block[k, j]).   // get multiplication result via loockup table
                                Substring(2, 2));    // remove 0x
                        }
                        sum = sum ^ temp;
                    }
                    result[i, j] = sum;
                }
            }
            return result;
        }
        public static string dec_last_round(string cipher_text, string key)
        {
            string[,] round_cipher = constants.string_to_arr(cipher_text);
            int[,] round_cipher_int = constants.hex_to_dec(round_cipher);
            string[,] key1_arr = constants.key_string_to_arr(key);
            int[,] key1_int = constants.hex_to_dec(key1_arr);

            /*int[,] inv_shifted_int = Inverse_Shift_Row(round_cipher_int);

            string[,] subbed = sub_bytes_2d(inv_shifted_int,constants.get_inverse_s_box());
            int[,] subbed_int = constants.hex_to_dec(subbed);


            
            */
            int[,] round1 = AddRoundKey(round_cipher_int, key1_int);
            string[,] res = constants.dec_to_hex(round1);
            string result = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += (res[j, i]);
                }
            }
            return result;
        }

        #region GET KEYS FUNCTIONS
        public static string[] generate_keys(string initial_key)
        {
            int[] round_constant = { 1, 0, 0, 0 };
            int[] rci = { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
            string[] keys = new string[11];
            keys[0] = initial_key;
            for (int i = 1; i < 11; i++)
            {
                round_constant[0] = rci[i - 1];
                keys[i] = get_key_schedule(keys[i - 1], round_constant);
            }
            return keys;
        }
        public static string get_key_schedule(string key, int[] round_constant)
        {
            string[,] key_arr = constants.string_to_arr(key);
            int[,] key_int = constants.hex_to_dec(key_arr);
            int[] w0 = get_quarter(key_int, 0);
            int[] w1 = get_quarter(key_int, 1);
            int[] w2 = get_quarter(key_int, 2);
            int[] w3 = get_quarter(key_int, 3);

            int[] g_w3 = key_shift_left(w3);
            string[] g_w3_ = sub_bytes_1d(g_w3,constants.get_s_box());
            int[] w3_int = constants.hex_to_dec(g_w3_);

            int[] final_w3 = add_round_constant(w3_int, round_constant);

            int[] w4 = xor(w0, final_w3);
            int[] w5 = xor(w1, w4);
            int[] w6 = xor(w2, w5);
            int[] w7 = xor(w3, w6);

            int[,] intial_key = combine_parts(w4, w5, w6, w7);
            string[,] result = constants.dec_to_hex(intial_key);

            string res = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    res += result[i, j];
                }
            }
            return res;
        }

        public static int[,] combine_parts(int[] p1, int[] p2, int[] p3, int[] p4)
        {
            int[,] result = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                result[0, i] = p1[i];
                result[1, i] = p2[i];
                result[2, i] = p3[i];
                result[3, i] = p4[i];
            }
            return result;
        }



        public static int[] xor(int[] arr1, int[] arr2)
        {
            int[] result = new int[4];
            for (int i = 0; i < 4; i++)
            {
                result[i] = arr1[i] ^ arr2[i];
            }
            return result;
        }



        public static int[] get_quarter(int[,] arr, int index)
        {
            int[] result = new int[4];
            for (int i = 0; i < 4; i++)
            {
                result[i] = arr[index, i];
            }
            return result;
        }


        public static int[] key_shift_left(int[] key)
        {
            int[] result = new int[4];
            result[0] = key[1];
            result[1] = key[2];
            result[2] = key[3];
            result[3] = key[0];

            return result;
        }
        public static int[] add_round_constant(int[] key, int[] constant)
        {
            int[] result = new int[4];
            for (int i = 0; i < 4; i++)
            {
                result[i] = key[i] ^ constant[i];
            }
            return result;
        }
        #endregion


        #region ARRAY MANIPULATION
        public static string[,] sub_bytes_2d(int[,] text, string[] box)
        {
            string[,] result = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                int[] temp = { text[i, 0], text[i, 1], text[i, 2], text[i, 3] };
                string[] temp_str = sub_bytes_1d(temp, box);
                result[i, 0] = temp_str[0];
                result[i, 1] = temp_str[1];
                result[i, 2] = temp_str[2];
                result[i, 3] = temp_str[3];
            }
            return result;
        }
        public static string[] sub_bytes_1d(int[] text_block, string[] box)
        {
            //assuming both text_block, s_box are converted to decimal,
            //1 dimensional arrays of size 16
            string[] result = new string[4];
            for (int i = 0; i < text_block.Length; i++)
            {
                int index = text_block[i];
                result[i] = (box[index]);
            }
            return result;
        }
        public static int[,] mix_columns(int[,] text_block, int[,] matrix)
        {
            //assuming text_block, and matrix are converted to decimal,
            //2 dimensional arrays of size 4*4
            int[,] result = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int sum = 0;
                    for (int k = 0; k < 4; k++)
                    {
                        int temp = (matrix[i, k] * text_block[k, j]);
                        if (temp >= 256 || matrix[i, k] == 3)
                        {
                            if (matrix[i, k] == 2)
                            {
                                temp ^= 27;
                                temp %= 256;
                            }
                            else if (matrix[i, k] == 3)
                            {
                                int temp2 = 2 * text_block[k, j];
                                if (temp2 >= 256)
                                {
                                    temp2 ^= 27;
                                    temp = text_block[k, j] ^ temp2;
                                    temp %= 256;
                                }
                                else
                                {
                                    temp = text_block[k, j] ^ temp2;
                                }
                            }
                        }
                        sum = sum ^ temp;
                    }
                    result[i, j] = sum;
                }
            }
            return result;
        }

        public static int[,] AddRoundKey(int[,] state_matrix, int[,] round_key)
        {
            int[,] result = new int[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result[i, j] = state_matrix[i, j] ^ round_key[i, j];
                }
            }
            return result;
        }

        public static int[,] ShiftRows(int[,] mat)//matrix 4*4
        {

            int[,] newMat = new int[,]{
                {mat[0,0],mat[0,1],mat[0,2],mat[0,3] },
                {mat[1,1],mat[1,2],mat[1,3],mat[1,0] },
                {mat[2,2],mat[2,3],mat[2,0],mat[2,1] },
                {mat[3,3],mat[3,0],mat[3,1],mat[3,2] },
            };

            return newMat;
        }
        #endregion

    }
    #region CONSTANTS
    public class constants
    {
        public static string galois_multiply_by_9(int num)
        {
            string[] galois_lookup_table = { "0x00", "0x09", "0x12", "0x1b", "0x24", "0x2d", "0x36", "0x3f", "0x48", "0x41", "0x5a", "0x53", "0x6c", "0x65",
                    "0x7e", "0x77", "0x90", "0x99", "0x82", "0x8b", "0xb4", "0xbd", "0xa6", "0xaf", "0xd8", "0xd1", "0xca", "0xc3", "0xfc", "0xf5", "0xee", "0xe7",
                    "0x3b", "0x32", "0x29", "0x20", "0x1f", "0x16", "0x0d", "0x04", "0x73", "0x7a", "0x61", "0x68", "0x57", "0x5e", "0x45", "0x4c", "0xab", "0xa2",
                    "0xb9", "0xb0", "0x8f", "0x86", "0x9d", "0x94", "0xe3", "0xea", "0xf1", "0xf8", "0xc7", "0xce", "0xd5", "0xdc", "0x76", "0x7f", "0x64", "0x6d",
                    "0x52", "0x5b", "0x40", "0x49", "0x3e", "0x37", "0x2c", "0x25", "0x1a", "0x13", "0x08", "0x01", "0xe6", "0xef", "0xf4", "0xfd", "0xc2", "0xcb",
                    "0xd0", "0xd9", "0xae", "0xa7", "0xbc", "0xb5", "0x8a", "0x83", "0x98", "0x91", "0x4d", "0x44", "0x5f", "0x56", "0x69", "0x60", "0x7b", "0x72",
                    "0x05", "0x0c", "0x17", "0x1e", "0x21", "0x28", "0x33", "0x3a", "0xdd", "0xd4", "0xcf", "0xc6", "0xf9", "0xf0", "0xeb", "0xe2", "0x95", "0x9c",
                    "0x87", "0x8e", "0xb1", "0xb8", "0xa3", "0xaa", "0xec", "0xe5", "0xfe", "0xf7", "0xc8", "0xc1", "0xda", "0xd3", "0xa4", "0xad", "0xb6",
                    "0xbf", "0x80", "0x89", "0x92", "0x9b", "0x7c", "0x75", "0x6e", "0x67", "0x58", "0x51", "0x4a", "0x43", "0x34", "0x3d", "0x26", "0x2f", "0x10",
                    "0x19", "0x02", "0x0b", "0xd7", "0xde", "0xc5", "0xcc", "0xf3", "0xfa", "0xe1", "0xe8", "0x9f", "0x96", "0x8d", "0x84", "0xbb", "0xb2", "0xa9",
                    "0xa0", "0x47", "0x4e", "0x55", "0x5c", "0x63", "0x6a", "0x71", "0x78", "0x0f", "0x06", "0x1d", "0x14", "0x2b", "0x22", "0x39", "0x30", "0x9a",
                    "0x93", "0x88", "0x81", "0xbe", "0xb7", "0xac", "0xa5", "0xd2", "0xdb", "0xc0", "0xc9", "0xf6", "0xff", "0xe4", "0xed", "0x0a", "0x03", "0x18",
                    "0x11", "0x2e", "0x27", "0x3c", "0x35", "0x42", "0x4b", "0x50", "0x59", "0x66", "0x6f", "0x74", "0x7d", "0xa1", "0xa8", "0xb3", "0xba", "0x85",
                    "0x8c", "0x97", "0x9e", "0xe9", "0xe0", "0xfb", "0xf2", "0xcd", "0xc4", "0xdf", "0xd6", "0x31", "0x38", "0x23", "0x2a", "0x15", "0x1c", "0x07",
                    "0x0e", "0x79", "0x70", "0x6b", "0x62", "0x5d", "0x54", "0x4f", "0x46" };


            return galois_lookup_table[num];
        }
        public static string galois_multiply_by_11(int num)
        {
            string[] galois_lookup_table = { "0x00", "0x0b", "0x16", "0x1d", "0x2c", "0x27", "0x3a", "0x31", "0x58", "0x53", "0x4e", "0x45", "0x74", "0x7f",
                    "0x62", "0x69", "0xb0", "0xbb", "0xa6", "0xad", "0x9c", "0x97", "0x8a", "0x81", "0xe8", "0xe3", "0xfe", "0xf5", "0xc4", "0xcf", "0xd2", "0xd9",
                    "0x7b", "0x70", "0x6d", "0x66", "0x57", "0x5c", "0x41", "0x4a", "0x23", "0x28", "0x35", "0x3e", "0x0f", "0x04", "0x19", "0x12", "0xcb", "0xc0",
                    "0xdd", "0xd6", "0xe7", "0xec", "0xf1", "0xfa", "0x93", "0x98", "0x85", "0x8e", "0xbf", "0xb4", "0xa9", "0xa2", "0xf6", "0xfd", "0xe0", "0xeb",
                    "0xda", "0xd1", "0xcc", "0xc7", "0xae", "0xa5", "0xb8", "0xb3", "0x82", "0x89", "0x94", "0x9f", "0x46", "0x4d", "0x50", "0x5b", "0x6a", "0x61",
                    "0x7c", "0x77", "0x1e", "0x15", "0x08", "0x03", "0x32", "0x39", "0x24", "0x2f", "0x8d", "0x86", "0x9b", "0x90", "0xa1", "0xaa", "0xb7", "0xbc",
                    "0xd5", "0xde", "0xc3", "0xc8", "0xf9", "0xf2", "0xef", "0xe4", "0x3d", "0x36", "0x2b", "0x20", "0x11", "0x1a", "0x07", "0x0c", "0x65", "0x6e",
                    "0x73", "0x78", "0x49", "0x42", "0x5f", "0x54", "0xf7", "0xfc", "0xe1", "0xea", "0xdb", "0xd0", "0xcd", "0xc6", "0xaf", "0xa4", "0xb9", "0xb2",
                    "0x83", "0x88", "0x95", "0x9e", "0x47", "0x4c", "0x51", "0x5a", "0x6b", "0x60", "0x7d", "0x76", "0x1f", "0x14", "0x09", "0x02", "0x33", "0x38",
                    "0x25", "0x2e", "0x8c", "0x87", "0x9a", "0x91", "0xa0", "0xab", "0xb6", "0xbd", "0xd4", "0xdf", "0xc2", "0xc9", "0xf8", "0xf3", "0xee", "0xe5",
                    "0x3c", "0x37", "0x2a", "0x21", "0x10", "0x1b", "0x06", "0x0d", "0x64", "0x6f", "0x72", "0x79", "0x48", "0x43", "0x5e", "0x55", "0x01", "0x0a",
                    "0x17", "0x1c", "0x2d", "0x26", "0x3b", "0x30", "0x59", "0x52", "0x4f", "0x44", "0x75", "0x7e", "0x63", "0x68", "0xb1", "0xba", "0xa7", "0xac",
                    "0x9d", "0x96", "0x8b", "0x80", "0xe9", "0xe2", "0xff", "0xf4", "0xc5", "0xce", "0xd3", "0xd8", "0x7a", "0x71", "0x6c", "0x67", "0x56", "0x5d",
                    "0x40", "0x4b", "0x22", "0x29", "0x34", "0x3f", "0x0e", "0x05", "0x18", "0x13", "0xca", "0xc1", "0xdc", "0xd7", "0xe6", "0xed", "0xf0", "0xfb",
                    "0x92", "0x99", "0x84", "0x8f", "0xbe", "0xb5", "0xa8", "0xa3" };


            return galois_lookup_table[num];
        }
        public static string galois_multiply_by_13(int num)
        {
            string[] galois_lookup_table = { "0x00", "0x0d", "0x1a", "0x17", "0x34", "0x39", "0x2e", "0x23", "0x68", "0x65", "0x72", "0x7f", "0x5c", "0x51",
                    "0x46", "0x4b", "0xd0", "0xdd", "0xca", "0xc7", "0xe4", "0xe9", "0xfe", "0xf3", "0xb8", "0xb5", "0xa2", "0xaf", "0x8c", "0x81", "0x96", "0x9b",
                    "0xbb", "0xb6", "0xa1", "0xac", "0x8f", "0x82", "0x95", "0x98", "0xd3", "0xde", "0xc9", "0xc4", "0xe7", "0xea", "0xfd", "0xf0", "0x6b", "0x66",
                    "0x71", "0x7c", "0x5f", "0x52", "0x45", "0x48", "0x03", "0x0e", "0x19", "0x14", "0x37", "0x3a", "0x2d", "0x20", "0x6d", "0x60", "0x77", "0x7a",
                    "0x59", "0x54", "0x43", "0x4e", "0x05", "0x08", "0x1f", "0x12", "0x31", "0x3c", "0x2b", "0x26", "0xbd", "0xb0", "0xa7", "0xaa", "0x89", "0x84",
                    "0x93", "0x9e", "0xd5", "0xd8", "0xcf", "0xc2", "0xe1", "0xec", "0xfb", "0xf6", "0xd6", "0xdb", "0xcc", "0xc1", "0xe2", "0xef", "0xf8", "0xf5",
                    "0xbe", "0xb3", "0xa4", "0xa9", "0x8a", "0x87", "0x90", "0x9d", "0x06", "0x0b", "0x1c", "0x11", "0x32", "0x3f", "0x28", "0x25", "0x6e", "0x63",
                    "0x74", "0x79", "0x5a", "0x57", "0x40", "0x4d", "0xda", "0xd7", "0xc0", "0xcd", "0xee", "0xe3", "0xf4", "0xf9", "0xb2", "0xbf", "0xa8", "0xa5",
                    "0x86", "0x8b", "0x9c", "0x91", "0x0a", "0x07", "0x10", "0x1d", "0x3e", "0x33", "0x24", "0x29", "0x62", "0x6f", "0x78", "0x75", "0x56", "0x5b",
                    "0x4c", "0x41", "0x61", "0x6c", "0x7b", "0x76", "0x55", "0x58", "0x4f", "0x42", "0x09", "0x04", "0x13", "0x1e", "0x3d", "0x30", "0x27", "0x2a",
                    "0xb1", "0xbc", "0xab", "0xa6", "0x85", "0x88", "0x9f", "0x92", "0xd9", "0xd4", "0xc3", "0xce", "0xed", "0xe0", "0xf7", "0xfa", "0xb7", "0xba",
                    "0xad", "0xa0", "0x83", "0x8e", "0x99", "0x94", "0xdf", "0xd2", "0xc5", "0xc8", "0xeb", "0xe6", "0xf1", "0xfc", "0x67", "0x6a", "0x7d", "0x70",
                    "0x53", "0x5e", "0x49", "0x44", "0x0f", "0x02", "0x15", "0x18", "0x3b", "0x36", "0x21", "0x2c", "0x0c", "0x01", "0x16", "0x1b", "0x38", "0x35",
                    "0x22", "0x2f", "0x64", "0x69", "0x7e", "0x73", "0x50", "0x5d", "0x4a", "0x47", "0xdc", "0xd1", "0xc6", "0xcb", "0xe8", "0xe5", "0xf2", "0xff",
                    "0xb4", "0xb9", "0xae", "0xa3", "0x80", "0x8d", "0x9a", "0x97" };



            return galois_lookup_table[num];
        }
        public static string galois_multiply_by_14(int num)
        {
            string[] galois_lookup_table = { "0x00", "0x0e", "0x1c", "0x12", "0x38", "0x36", "0x24", "0x2a", "0x70", "0x7e", "0x6c", "0x62", "0x48", "0x46",
                    "0x54", "0x5a", "0xe0", "0xee", "0xfc", "0xf2", "0xd8", "0xd6", "0xc4", "0xca", "0x90", "0x9e", "0x8c", "0x82", "0xa8", "0xa6", "0xb4", "0xba",
                    "0xdb", "0xd5", "0xc7", "0xc9", "0xe3", "0xed", "0xff", "0xf1", "0xab", "0xa5", "0xb7", "0xb9", "0x93", "0x9d", "0x8f", "0x81", "0x3b", "0x35",
                    "0x27", "0x29", "0x03", "0x0d", "0x1f", "0x11", "0x4b", "0x45", "0x57", "0x59", "0x73", "0x7d", "0x6f", "0x61", "0xad", "0xa3", "0xb1", "0xbf",
                    "0x95", "0x9b", "0x89", "0x87", "0xdd", "0xd3", "0xc1", "0xcf", "0xe5", "0xeb", "0xf9", "0xf7", "0x4d", "0x43", "0x51", "0x5f", "0x75", "0x7b",
                    "0x69", "0x67", "0x3d", "0x33", "0x21", "0x2f", "0x05", "0x0b", "0x19", "0x17", "0x76", "0x78", "0x6a", "0x64", "0x4e", "0x40", "0x52", "0x5c",
                    "0x06", "0x08", "0x1a", "0x14", "0x3e", "0x30", "0x22", "0x2c", "0x96", "0x98", "0x8a", "0x84", "0xae", "0xa0", "0xb2", "0xbc", "0xe6", "0xe8",
                    "0xfa", "0xf4", "0xde", "0xd0", "0xc2", "0xcc", "0x41", "0x4f", "0x5d", "0x53", "0x79", "0x77", "0x65", "0x6b", "0x31", "0x3f", "0x2d", "0x23",
                    "0x09", "0x07", "0x15", "0x1b", "0xa1", "0xaf", "0xbd", "0xb3", "0x99", "0x97", "0x85", "0x8b", "0xd1", "0xdf", "0xcd", "0xc3", "0xe9", "0xe7",
                    "0xf5", "0xfb", "0x9a", "0x94", "0x86", "0x88", "0xa2", "0xac", "0xbe", "0xb0", "0xea", "0xe4", "0xf6", "0xf8", "0xd2", "0xdc", "0xce", "0xc0",
                    "0x7a", "0x74", "0x66", "0x68", "0x42", "0x4c", "0x5e", "0x50", "0x0a", "0x04", "0x16", "0x18", "0x32", "0x3c", "0x2e", "0x20", "0xec", "0xe2",
                    "0xf0", "0xfe", "0xd4", "0xda", "0xc8", "0xc6", "0x9c", "0x92", "0x80", "0x8e", "0xa4", "0xaa", "0xb8", "0xb6", "0x0c", "0x02", "0x10", "0x1e",
                    "0x34", "0x3a", "0x28", "0x26", "0x7c", "0x72", "0x60", "0x6e", "0x44", "0x4a", "0x58", "0x56", "0x37", "0x39", "0x2b", "0x25", "0x0f", "0x01",
                    "0x13", "0x1d", "0x47", "0x49", "0x5b", "0x55", "0x7f", "0x71", "0x63", "0x6d", "0xd7", "0xd9", "0xcb", "0xc5", "0xef", "0xe1", "0xf3", "0xfd",
                    "0xa7", "0xa9", "0xbb", "0xb5", "0x9f", "0x91", "0x83", "0x8d" };


            return galois_lookup_table[num];
        }
        public static string[,] string_to_arr(string s)
        {
            string[,] arr = new string[4, 4];
            int index = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    arr[i, j] = s.Substring(index, 2);
                    index += 2;
                }
            }
            return arr;
        }
        public static string[,] key_string_to_arr(string s)
        {
            string[,] arr = new string[4, 4];
            int index = 0;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    arr[j, i] = s.Substring(index, 2);
                    index += 2;
                }
            }
            return arr;
        }
        public static string arr_to_string(string[,] arr)
        {
            string result = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    result += arr[i, j];
                }
            }
            return result;
        }
        public static int[] hex_to_dec(string[] hex)
        {
            int[] result = new int[4];

            Dictionary<char, int> chars = new Dictionary<char, int>();
            chars.Add('0', 0);
            chars.Add('1', 1);
            chars.Add('2', 2);
            chars.Add('3', 3);
            chars.Add('4', 4);
            chars.Add('5', 5);
            chars.Add('6', 6);
            chars.Add('7', 7);
            chars.Add('8', 8);
            chars.Add('9', 9);
            chars.Add('A', 10);
            chars.Add('B', 11);
            chars.Add('C', 12);
            chars.Add('D', 13);
            chars.Add('E', 14);
            chars.Add('F', 15);

            chars.Add('a', 10);
            chars.Add('b', 11);
            chars.Add('c', 12);
            chars.Add('d', 13);
            chars.Add('e', 14);
            chars.Add('f', 15);

            for (int i = 0; i < 4; i++)
            {
                int sum = chars[hex[i][0]] * 16 + chars[hex[i][1]];
                result[i] = sum;
            }
            return result;
        }
        public static int hex_to_dec(string hex)
        {
            int result = 0;

            Dictionary<char, int> chars = new Dictionary<char, int>();
            chars.Add('0', 0);
            chars.Add('1', 1);
            chars.Add('2', 2);
            chars.Add('3', 3);
            chars.Add('4', 4);
            chars.Add('5', 5);
            chars.Add('6', 6);
            chars.Add('7', 7);
            chars.Add('8', 8);
            chars.Add('9', 9);
            chars.Add('A', 10);
            chars.Add('B', 11);
            chars.Add('C', 12);
            chars.Add('D', 13);
            chars.Add('E', 14);
            chars.Add('F', 15);

            chars.Add('a', 10);
            chars.Add('b', 11);
            chars.Add('c', 12);
            chars.Add('d', 13);
            chars.Add('e', 14);
            chars.Add('f', 15);
            result = chars[hex[0]] * 16 + chars[hex[1]];


            return result;
        }
        public static int[,] hex_to_dec(string[,] hex)
        {
            //given array 4*4 of lower case, string hexa values, each string has 2 characters

            int[,] result = new int[4, 4];

            Dictionary<char, int> chars = new Dictionary<char, int>();
            chars.Add('0', 0);
            chars.Add('1', 1);
            chars.Add('2', 2);
            chars.Add('3', 3);
            chars.Add('4', 4);
            chars.Add('5', 5);
            chars.Add('6', 6);
            chars.Add('7', 7);
            chars.Add('8', 8);
            chars.Add('9', 9);
            chars.Add('A', 10);
            chars.Add('B', 11);
            chars.Add('C', 12);
            chars.Add('D', 13);
            chars.Add('E', 14);
            chars.Add('F', 15);

            chars.Add('a', 10);
            chars.Add('b', 11);
            chars.Add('c', 12);
            chars.Add('d', 13);
            chars.Add('e', 14);
            chars.Add('f', 15);

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    try
                    {
                        int sum = chars[hex[i, j][0]] * 16 + chars[hex[i, j][1]];
                        result[i, j] = sum;
                    }
                    catch
                    {
                        Console.Write(hex[i, j][0]);
                        Console.WriteLine(hex[i, j][1]);
                        Console.WriteLine("bug1");
                    }
                }
            }
            return result;

        }
        public static string[,] dec_to_hex(int[,] dec)
        {
            //given array 4*4 of integer values

            string[,] result = new string[4, 4];

            Dictionary<int, string> chars = new Dictionary<int, string>();
            chars.Add(0, "0");
            chars.Add(1, "1");
            chars.Add(2, "2");
            chars.Add(3, "3");
            chars.Add(4, "4");
            chars.Add(5, "5");
            chars.Add(6, "6");
            chars.Add(7, "7");
            chars.Add(8, "8");
            chars.Add(9, "9");
            chars.Add(10, "A");
            chars.Add(11, "B");
            chars.Add(12, "C");
            chars.Add(13, "D");
            chars.Add(14, "E");
            chars.Add(15, "F");


            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string sum = chars[dec[i, j] / 16] + chars[dec[i, j] % 16];
                    result[i, j] = sum;

                }
            }
            return result;

        }
        public static string[] get_s_box()
        {
            string[] s_box =
               {
            "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76",
            "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0",
            "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15",
            "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75",
            "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84",
            "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF",
            "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8",
            "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2",
            "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73",
            "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB",
            "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79",
            "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08",
            "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A",
            "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E",
            "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF",
            "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" };
            return s_box;
        }
        public static string[] get_inverse_s_box()
        {
            string[] inverse_s_box =
            {
                    "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb",
                    "7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb",
                    "54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e",
                    "08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25",
                    "72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92",
                    "6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84",
                    "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06",
                    "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b",
                    "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73",
                    "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e",
                    "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b",
                    "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4",
                    "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f",
                    "60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef",
                    "a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61",
                    "17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d"
                };
            return inverse_s_box;
        }
        public static int[,] mix_columns_matrix()
        {
            int[,] matrix = { {2, 3, 1, 1 },
                                {1, 2, 3, 1 },
                                {1, 1, 2, 3 },
                                {3, 1, 1, 2 } };
            return matrix;
        }
        public static int[,] inverse_mix_columns_matrix()
        {
            int[,] matrix = { {14, 11, 13, 9 },
                                {9, 14, 11, 13 },
                                {13, 9, 14, 11 },
                                {11, 13, 9, 14 } };
            return matrix;
        }
    }
    #endregion
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        public List<KeyValuePair<string, string>> key_rounds = new List<KeyValuePair<string, string>>();
        public List<KeyValuePair<string, string>> lift_right = new List<KeyValuePair<string, string>>();
        public List<string> keys = new List<string>();

        public string generate_r(string L, string R, string k)
        {
            string ER = expand(R);
            string tmp_f = xor(ER, k);

            List<string> Blocks = new List<string>();

            int cnt = 0;
            string tmp_B = "";
            for (int i = 0; i < tmp_f.Length; i++)
            {
                if (cnt == 6)
                {
                    Blocks.Add(tmp_B);
                    tmp_B = "";
                    cnt = 0;
                }
                tmp_B += tmp_f[i];
                cnt++;
            }
            Blocks.Add(tmp_B);
            string s = "";
            for (int i = 0; i < Blocks.Count; i++)
            {
                int row = get_pos((Blocks[i][0].ToString() + Blocks[i][5].ToString()));
                int col = get_pos((Blocks[i].Substring(1, 4)).ToString());
                int sb = 0;
                if (i == 0)
                    sb = constants.get_s1()[row, col];
                if (i == 1)
                    sb = constants.get_s2()[row, col];
                if (i == 2)
                    sb = constants.get_s3()[row, col];
                if (i == 3)
                    sb = constants.get_s4()[row, col];
                if (i == 4)
                    sb = constants.get_s5()[row, col];
                if (i == 5)
                    sb = constants.get_s6()[row, col];
                if (i == 6)
                    sb = constants.get_s7()[row, col];
                if (i == 7)
                    sb = constants.get_s8()[row, col];
                s += constants.convert(sb).ToString();
            }

            string f = "";

            for (int i = 0; i < 32; i++)
                f += s[constants.get_Permutation()[i / 4, i % 4] - 1];

            string New_R = xor(L, f);
            return New_R;
        }

        public int get_pos(string pos)
        {
            int ans = 0;
            int idx = 0;
            for (int i = pos.Length - 1; i >= 0; i--)
                ans += ((int)Math.Pow(2, idx++) * (pos[i] - '0'));
            return ans;
        }
        public string expand(string R)
        {
            string New_R = "";
            for (int i = 0; i < 48; i++)
                New_R += R[constants.get_eBit()[i / 6, i % 6] - 1];
            return New_R;
        }
        public string xor(string a, string b)
        {
            string res = "";
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] == b[i])
                    res += '0';
                else
                    res += '1';
            }
            return res;
        }
        public string sl1(string s)
        {
            return s.Substring(1) + s.Substring(0, 1);
        }
        public string sl2(string s)
        {
            return s.Substring(2) + s.Substring(0, 2);
        }

        public string get_key(string key)
        {
            string New_key = "";
            for (int i = 0; i < 56; i++)
                New_key += key[constants.get_pc1()[i / 7, i % 7] - 1];
            return New_key;
        }
        public string generate_key(string key)
        {
            string New_key = "";
            for (int i = 0; i < 48; i++)
                New_key += key[constants.get_pc2()[i / 6, i % 6] - 1];
            return New_key;
        }

        public string permute_ip(string M)
        {
            string tmp = "";
            for (int i = 2; i < M.Length; i++)
            {
                tmp += constants.convert(M[i]);
            }
            string New_M = "";
            for (int i = 0; i < 64; i++)
                New_M += tmp[constants.get_IP()[i / 8, i % 8] - 1];
            return New_M;
        }

        public override string Decrypt(string cipherText, string key)
        {

            //generate c and d
            string tmp = "";
            for (int i = 2; i < key.Length; i++)
            {
                tmp += constants.convert(key[i]);
            }

            string New_key = get_key(tmp);
            string C0 = New_key.Substring(0, 28);
            string D0 = New_key.Substring(28, 28);
            keys.Add(generate_key(C0 + D0));
            key_rounds.Add(new KeyValuePair<string, string>(C0, D0));
            for (int i = 1; i <= 16; i++)
            {
                if (i == 1 || i == 2 || i == 9 || i == 16)
                {
                    string tmp1 = sl1(key_rounds[i - 1].Key);
                    string tmp2 = sl1(key_rounds[i - 1].Value);
                    key_rounds.Add(new KeyValuePair<string, string>(tmp1, tmp2));
                    keys.Add(generate_key(tmp1 + tmp2));
                }
                else
                {
                    string tmp1 = sl2(key_rounds[i - 1].Key);
                    string tmp2 = sl2(key_rounds[i - 1].Value);
                    key_rounds.Add(new KeyValuePair<string, string>(tmp1, tmp2));
                    keys.Add(generate_key(tmp1 + tmp2));
                }
            }

            string IP = permute_ip(cipherText);
            string L0 = IP.Substring(0, 32);
            string R0 = IP.Substring(32, 32);
            lift_right.Add(new KeyValuePair<string, string>(L0, R0));
            for (int i = 1; i <= 16; i++)
            {
                string L = lift_right[i - 1].Value;
                string R = generate_r(lift_right[i - 1].Key, lift_right[i - 1].Value, keys[keys.Count - i]);
                lift_right.Add(new KeyValuePair<string, string>(L, R));
            }
            string RL = lift_right[16].Value + lift_right[16].Key;
            string final = "";
            for (int i = 0; i < 64; i++)
                final += RL[constants.get_IP_1()[i / 8, i % 8] - 1];
            string pt = "0x";
            for (int i = 0; i < 64; i += 4)
            {
                string temp = constants.convert(final.Substring(i, 4));
                pt += temp;
            }
            return pt;
        }
        public override string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            int[,] PC_1 = constants.get_pc1();
            int[,] PC_2 = constants.get_pc2();
            int[,] s1 = constants.get_s1();
            int[,] s2 = constants.get_s2();
            int[,] s3 = constants.get_s3();
            int[,] s4 = constants.get_s4();
            int[,] s5 = constants.get_s5();
            int[,] s6 = constants.get_s6();
            int[,] s7 = constants.get_s7();
            int[,] s8 = constants.get_s8();
            int[,] Permutation = constants.get_Permutation();
            int[,] eBit = constants.get_eBit();
            int[,] IP = constants.get_IP();
            int[,] IP_1 = constants.get_IP_1();

            //The "PadLeft" method is used to add leading zeros to the binary string until it is 64 bits long
            long p = Convert.ToInt64(plainText, 16);
            string binaryPlain = Convert.ToString(p, 2).PadLeft(64, '0');
            long k = Convert.ToInt64(key, 16);
            string binaryKey = Convert.ToString(k, 2).PadLeft(64, '0');

            string Lm = "";
            string Rm = "";
            int half_plain = binaryPlain.Length / 2;

            for (int i = 0; i < half_plain; i++)
            {
                Lm += binaryPlain[i];
                Rm += binaryPlain[i + half_plain];
            }

            //permutate key by pc-1
            string permutateKey = get_keyIP(binaryKey, PC_1);
            List<string> C = new List<string>();
            List<string> D = new List<string>();


            string c = "";
            string d = "";
            for (int i = 0; i < 28; i++)
            {
                c += permutateKey[i];
                d += permutateKey[i + 28];
            }

            string temp;
            for (int i = 0; i <= 16; i++)
            {
                C.Add(c);
                D.Add(d);
                temp = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    temp += c[0];
                    c = c.Remove(0, 1);
                    c += temp;

                    temp = "";
                    temp += d[0];
                    d = d.Remove(0, 1);
                    d += temp;
                }

                else
                {
                    for (int v = 0; v < 2; v++)
                        temp += c[v];
                    c = c.Remove(0, 2);
                    c += temp;

                    temp = "";
                    for (int v = 0; v < 2; v++)
                        temp += d[v];
                    d = d.Remove(0, 2);
                    d += temp;
                }
            }

            List<string> keys = new List<string>();
            for (int i = 0; i < D.Count; i++)
            {
                keys.Add(C[i] + D[i]);
            }

            List<string> nkeys = new List<string>();
            for (int z = 1; z < keys.Count; z++)
            {
                permutateKey = "";
                temp = keys[z];
                for (int i = 0; i < 8; i++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        permutateKey += temp[PC_2[i, j] - 1];
                    }
                }

                nkeys.Add(permutateKey);
            }

            //premutation by IP for plain text
            string ip = get_plainIP(binaryPlain, IP);

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = "";
            string r = "";
            for (int i = 0; i < 32; i++)
            {
                l += ip[i];
                r += ip[i + 32];
            }

            L.Add(l);
            R.Add(r);
            string x;
            string h;

            string ebit;
            string E_xor_K;
            List<string> sbox = new List<string>();
            string t;
            int row;
            int col;
            string tsb;
            string pp;
            string lf;

            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                E_xor_K = "";
                ebit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int y = 0; y < 6; y++)
                    {
                        ebit += r[eBit[j, y] - 1];
                    }
                }

                for (int m = 0; m < ebit.Length; m++)
                {
                    E_xor_K += (nkeys[i][m] ^ ebit[m]).ToString();
                }

                for (int n = 0; n < E_xor_K.Length; n += 6)
                {
                    t = "";
                    for (int y = n; y < 6 + n; y++)
                    {
                        if (6 + n <= E_xor_K.Length)
                            t += E_xor_K[y];
                    }

                    sbox.Add(t);
                }


                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    if (s == 0)
                        sb = s1[row, col];

                    if (s == 1)
                        sb = s2[row, col];

                    if (s == 2)
                        sb = s3[row, col];

                    if (s == 3)
                        sb = s4[row, col];

                    if (s == 4)
                        sb = s5[row, col];

                    if (s == 5)
                        sb = s6[row, col];

                    if (s == 6)
                        sb = s7[row, col];

                    if (s == 7)
                        sb = s8[row, col];

                    tsb += Convert.ToString(sb, 2).PadLeft(4, '0');
                }


                for (int o = 0; o < 8; o++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp += tsb[Permutation[o, j] - 1];
                    }
                }

                for (int z = 0; z < pp.Length; z++)
                {
                    lf += (pp[z] ^ l[z]).ToString();
                }

                r = lf;
                l = L[i + 1];
                R.Add(r);
            }

            string r16l16 = R[16] + L[16];
            string ct = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ct += r16l16[IP_1[i, j] - 1];
                }
            }
            string ciphertxt = "0x" + Convert.ToInt64(ct, 2).ToString("X");

            return ciphertxt;
        }

        public static string get_plainIP(string binaryPlain, int[,] IP)
        {
            string ip = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ip = ip + binaryPlain[IP[i, j] - 1];
                }
            }
            return ip;
        }
        public static string get_keyIP(string binaryKey, int[,] PC_1)
        {
            string permutateKey = "";
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    permutateKey += binaryKey[PC_1[i, j] - 1];
                }
            }
            return permutateKey;
        }

        public static class constants
        {
            static Dictionary<object, string> dict = new Dictionary<object, string>();
            public static string convert(object o)
            {
                dict.Clear();

                dict.Add(0, "0000");
                dict.Add(1, "0001");
                dict.Add(2, "0010");
                dict.Add(3, "0011");
                dict.Add(4, "0100");
                dict.Add(5, "0101");
                dict.Add(6, "0110");
                dict.Add(7, "0111");
                dict.Add(8, "1000");
                dict.Add(9, "1001");
                dict.Add(10, "1010");
                dict.Add(11, "1011");
                dict.Add(12, "1100");
                dict.Add(13, "1101");
                dict.Add(14, "1110");
                dict.Add(15, "1111");

                dict.Add('0', "0000");
                dict.Add('1', "0001");
                dict.Add('2', "0010");
                dict.Add('3', "0011");
                dict.Add('4', "0100");
                dict.Add('5', "0101");
                dict.Add('6', "0110");
                dict.Add('7', "0111");
                dict.Add('8', "1000");
                dict.Add('9', "1001");
                dict.Add('A', "1010");
                dict.Add('B', "1011");
                dict.Add('C', "1100");
                dict.Add('D', "1101");
                dict.Add('E', "1110");
                dict.Add('F', "1111");

                dict.Add("0000", "0");
                dict.Add("0001", "1");
                dict.Add("0010", "2");
                dict.Add("0011", "3");
                dict.Add("0100", "4");
                dict.Add("0101", "5");
                dict.Add("0110", "6");
                dict.Add("0111", "7");
                dict.Add("1000", "8");
                dict.Add("1001", "9");
                dict.Add("1010", "A");
                dict.Add("1011", "B");
                dict.Add("1100", "C");
                dict.Add("1101", "D");
                dict.Add("1110", "E");
                dict.Add("1111", "F");
                return dict[o];
            }

            public static int[,] get_pc1()
            {
                int[,] PC_1 = new int[8, 7] {
                { 57, 49, 41, 33, 25, 17, 9 },
                { 1, 58, 50, 42, 34, 26, 18 },
                { 10, 2, 59, 51, 43, 35, 27 },
                { 19, 11, 3, 60, 52, 44, 36 },
                { 63, 55, 47, 39, 31, 23, 15 },
                { 7, 62, 54, 46, 38, 30, 22 },
                { 14, 6, 61, 53, 45, 37, 29 },
                { 21, 13, 5, 28, 20, 12, 4 }
            };
                return PC_1;
            }
            public static int[,] get_pc2()
            {
                int[,] PC_2 = new int[8, 6] {
                { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 }
            };
                return PC_2;
            }
            public static int[,] get_s1()
            {
                int[,] s1 = new int[4, 16] {
                { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
            };
                return s1;
            }
            public static int[,] get_s2()
            {
                int[,] s2 = new int[4, 16] {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            };
                return s2;
            }
            public static int[,] get_s3()
            {
                int[,] s3 = new int[4, 16] {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            };
                return s3;
            }
            public static int[,] get_s4()
            {
                int[,] s4 = new int[4, 16] {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            };
                return s4;
            }
            public static int[,] get_s5()
            {
                int[,] s5 = new int[4, 16] {
                { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            };
                return s5;
            }
            public static int[,] get_s6()
            {
                int[,] s6 = new int[4, 16] {
                { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            };
                return s6;
            }
            public static int[,] get_s7()
            {
                int[,] s7 = new int[4, 16] {
                { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            };
                return s7;
            }
            public static int[,] get_s8()
            {
                int[,] s8 = new int[4, 16] {
                { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            };
                return s8;
            }
            public static int[,] get_Permutation()
            {
                int[,] Permutation = new int[8, 4] {
                { 16, 7, 20, 21 },
                { 29, 12, 28, 17 },
                { 1, 15, 23, 26 },
                { 5, 18, 31, 10 },
                { 2, 8, 24, 14 },
                { 32, 27, 3, 9 },
                { 19, 13, 30, 6 },
                { 22, 11, 4, 25 }
            };
                return Permutation;
            }
            public static int[,] get_eBit()
            {
                int[,] eBit = new int[8, 6] {
                { 32, 1, 2, 3, 4, 5 },
                { 4, 5, 6, 7, 8, 9 },
                { 8, 9, 10, 11, 12, 13 },
                { 12, 13, 14, 15, 16, 17 },
                { 16, 17, 18, 19, 20, 21 },
                { 20, 21, 22, 23, 24, 25 },
                { 24, 25, 26, 27, 28, 29 },
                { 28, 29, 30, 31, 32, 1 }
            };
                return eBit;
            }
            public static int[,] get_IP()
            {
                int[,] IP = new int[8, 8] {
                { 58, 50, 42, 34, 26, 18, 10, 2 },
                { 60, 52, 44, 36, 28, 20, 12, 4 },
                { 62, 54, 46, 38, 30, 22, 14, 6 },
                { 64, 56, 48, 40, 32, 24, 16, 8 },
                { 57, 49, 41, 33, 25, 17, 9, 1 },
                { 59, 51, 43, 35, 27, 19, 11, 3 },
                { 61, 53, 45, 37, 29, 21, 13, 5 },
                { 63, 55, 47, 39, 31, 23, 15, 7 }
            };
                return IP;
            }
            public static int[,] get_IP_1()
            {
                int[,] IP_1 = new int[8, 8] {
                { 40, 8, 48, 16, 56, 24, 64, 32 },
                { 39, 7, 47, 15, 55, 23, 63, 31 },
                { 38, 6, 46, 14, 54, 22, 62, 30 },
                { 37, 5, 45, 13, 53, 21, 61, 29 },
                { 36, 4, 44, 12, 52, 20, 60, 28 },
                { 35, 3, 43, 11, 51, 19, 59, 27 },
                { 34, 2, 42, 10, 50, 18, 58, 26 },
                { 33, 1, 41, 9, 49, 17, 57, 25 }
            };
                return IP_1;
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //make both plain and cipher lower alphabits 
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            Dictionary<char, char> key = new Dictionary<char, char>();

            //fill dictionary with empty values
            for (char i = 'a'; i <= 'z'; i++)
            {
                key.Add(i, ' ');
                // curr_char++;
            }
            //fill dictionary with cipher text
            for (int i = 0; i < plainText.Length; i++)
            {
                key[plainText[i]] = cipherText[i];


            }
            //create characters string to generate random char
            string characters = "abcdefghijklmnopqrstuvwxyz";
            string values = "";
            //make sequence of chars from explored cipher characters to generate random characters 
            for (char i = 'a'; i <= 'z'; i++)
            {
                if (key[i] != ' ')
                {
                    values += key[i];
                }
            }



            string str = "";
            for (char i = 'a'; i <= 'z'; i++)
            {
                //if the value is empty generate random value to the key
                if (key[i] == ' ')
                {
                    while (true)
                    {
                        Random rand = new Random();
                        int num = rand.Next(0, characters.Length);
                        //if the randomly generated char is not represented in values string which have sequence of chars that have found or
                        //not represented in any value of the dictionary it store in the dictionary
                        if (!values.Contains(characters[num]) && !key.Values.Contains(characters[num]))
                        {
                            key[i] = characters[num];
                            break;

                        }
                    }
                }
                //store the value of each key in string to return
                str += key[i];
            }




            return str;
        }

        public string Decrypt(string cipherText, string key)
        {
            char[] letter = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            cipherText = cipherText.ToLower();
            string plainText = "";

            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = 0;

                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == key[j])
                        break;
                    index++;
                }

                plainText += letter[index];
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();

            string cipherText = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                int index = 0;
                for (char c = 'a'; c <= 'z'; c++)
                {
                    if (plainText[i] == c)
                        break;
                    index++;
                }
                cipherText += key[index];
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string result = "";
            string freq_ordered = "etaoinsrhldcumfpgwybvkxjqz";
            SortedDictionary<char, int> frequency_count = new SortedDictionary<char, int>();
            for (int i = 0; i < cipher.Length; i++)
            {
                if (frequency_count.ContainsKey(cipher[i]))
                {
                    frequency_count[cipher[i]]++;
                }
                else
                {
                    frequency_count.Add(cipher[i], 1);
                }
            }

            Dictionary<char, char> map = new Dictionary<char, char>();
            int max_freq;
            char max_char = 'a';
            int index = 0;
            while (frequency_count.Count > 0)
            {
                max_freq = -1;
                foreach (KeyValuePair<char, int> entry in frequency_count)
                {
                    if (entry.Value > max_freq)
                    {
                        max_char = entry.Key;
                        max_freq = entry.Value;
                    }
                }
                map.Add(max_char, freq_ordered[index++]);
                frequency_count.Remove(max_char);

            }


            for (int i = 0; i < cipher.Length; i++)
            {
                result = result + map[cipher[i]];
            }
            return result;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            int counter = 0;
            char curr_char = 'a';
            //loop on each character in text
            for (int i = 0; i < plainText.Length; i++)
            {
                counter = 0;
                //char used to get the count
                curr_char = 'a';
                //loop on alphabits to get the index
                for (int j = 0; j < 26; j++)
                {
                    //if the current character equal character of plaintext we take the count of that char
                    if (curr_char == plainText[i])
                    {   //new char to store in cipher text
                        char temp = 'a';

                        int value = (counter + key) % 26;
                        //loop on alphabits to get character of specific number
                        for (int k = 0; k < 26; k++)
                        {
                            if (k == value)
                            {
                                cipherText += temp;
                                break;
                            }
                            temp++;
                        }

                        break;
                    }
                    curr_char++;
                    counter++;
                }
            }
            return cipherText;

        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string plain_text = "";
            int counter;
            char curr_char;
            for (int i = 0; i < cipherText.Length; i++)
            {
                curr_char = 'a';
                counter = 0;
                for (int j = 0; j < 26; j++)
                {
                    if (curr_char == cipherText[i])
                    {
                        counter = j;
                        break;
                    }
                    curr_char++;
                }
                int plain_num = counter - key;
                if (plain_num < 0)
                {
                    plain_num = plain_num + 26;
                }
                curr_char = 'a';
                for (int k = 0; k < plain_num; k++)
                {
                    curr_char++;
                }
                plain_text += curr_char;
            }
            return plain_text;
        }

        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int key = 0;
            string Cipher_temp = "";
            for (int i = 0; i < 26; i++)
            {
                Cipher_temp = Encrypt(plainText, key);
                if (cipherText == Cipher_temp)
                {
                    break;
                }
                key++;
            }

            return key;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int cI = cipherText[i] - 'A';
                int pI = plainText[i] - 'A';
                int kI = (cI - pI + 26) % 26;
                key += (char)(kI + 'A');
            }
            string subKey = "";
            string subKey2 = "";
            for (int j = 4; j < key.Length; j++)
            {
                if (j <= (key.Length - 4))
                {
                    subKey = key.Substring(j, 4);
                    subKey2 = key.Substring(0, 4);
                    if (subKey.Equals(subKey2))
                    {
                        key = key.Substring(0, j);
                        break;
                    }
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            string plaintext = "";
            int index = 0;

            for (int i = 0; i < cipherText.Length; i++)
            {
                char cipherChar = cipherText[i];
                char keyChar = key[index % key.Length]; // use modulus to repeat the key
                                                        // convert the key character to a shift value 
                int shiftval = keyChar - 'a';

                // Decrypt the current ciphertext character
                char plainChar = (char)((cipherChar - shiftval - 'a' + 26) % 26 + 'a');
                plaintext += plainChar;

                // Move to the next key character
                index++;
            }

            return plaintext;


            //   throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            string ciphertext = "";
            int index = 0;

            for (int i = 0; i < plainText.Length; i++)
            {
                //to get current char in plaintext
                char currentofplain = plainText[i];
                // use modulus to repeat the key if the key less than plaintext
                char keyChar = key[index % key.Length];
                // convert the key character to a shift value
                int shiftval = keyChar - 'a';
                // convert the current plaintext character to cipher char
                char cipherChar = (char)((currentofplain + shiftval - 'a') % 26 + 'a');
                ciphertext += cipherChar;

                // Move to the next key character
                index++;
            }

            return ciphertext;
            //  throw new NotImplementedException();
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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
            string subPlain = "";
            for (int j = 0; j < key.Length; j++)
            {
                if (j <= (key.Length - 4))
                {
                    subKey = key.Substring(j, 4);
                    subPlain = plainText.Substring(0, 4);
                    if (subKey.Equals(subPlain))
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

            string plaintext = "";
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            int KeyLen = key.Length;
            int counter = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (i == KeyLen)
                {
                    key += plaintext.Substring((counter));
                    KeyLen = key.Length;
                    counter = i;
                }

                int cI = cipherText[i] - 'A';
                int kI = key[i] - 'A';
                int pI = (cI - kI + 26) % 26;
                plaintext += (char)(pI + 'A');

            }

            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            string ciphertext = "";
            key = key + plainText;
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            for (int i = 0; i < plainText.Length; i++)
            {
                int pI = plainText[i] - 'A';
                int kI = key[i] - 'A';
                int cI = (pI + kI) % 26;
                ciphertext += (char)(cI + 'A');
            }

            return ciphertext;
        }
    }
}

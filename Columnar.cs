using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            SortedDictionary<int, int> sortedDictionary = new SortedDictionary<int, int>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            double plainTxtSize = plainText.Length;

            for (int z = 1; z < Int32.MaxValue; z++)
            {
                int c = 0;
                int width = z;
                double height = Math.Ceiling(plainTxtSize / z);
                string[,] pl = new string[(int)height, width];
                for (int i = 0; i < height; i++)
                {
                    for (int j = 0; j < z; j++)
                    {
                        if (c >= plainTxtSize)
                        {
                            pl[i, j] = "";
                        }
                        else
                        {
                            pl[i, j] = plainText[c].ToString();
                            c++;
                        }
                    }
                }
                List<string> mylist = new List<string>();
                for (int i = 0; i < z; i++)
                {
                    string word = "";
                    for (int j = 0; j < height; j++)
                    {
                        word += pl[j, i];
                    }
                    mylist.Add(word);
                }

                bool correctkey = true;
                string cipherCopy = (string)cipherText.Clone();
                for (int i = 0; i < mylist.Count; i++)
                {
                    int x = cipherCopy.IndexOf(mylist[i]);
                    if (x == -1)
                    {
                        correctkey = false;
                    }
                    else
                    {
                        sortedDictionary.Add(x, i + 1);
                    }
                }
                if (correctkey)
                    break;

            }
            List<int> key = new List<int>();
            Dictionary<int, int> newDictionary = new Dictionary<int, int>();

            for (int i = 0; i < sortedDictionary.Count; i++)
            {
                newDictionary.Add(sortedDictionary.ElementAt(i).Value, i + 1);
            }
            for (int i = 1; i < newDictionary.Count + 1; i++)
            {
                key.Add(newDictionary[i]);
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int column = key.Count;
            double size = cipherText.Length;
            int row = (int)(Math.Ceiling(size / column));
            char[,] encrypted_matrix = new char[row, column];

            List<int> k = new List<int> { };

            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (key[j] - 1 == i)
                    {
                        k.Add(j);
                        break;
                    }
                }
            }
            int index = 0;
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < row && index < cipherText.Length; j++)
                {
                    encrypted_matrix[j, k[i]] = cipherText[index];
                    index++;
                }
            }
            string plainText = "";
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    plainText += encrypted_matrix[i, j];
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //plainText = String.Concat(plainText.Where(c => !Char.IsWhiteSpace(c)));
            int column = key.Count;
            double size = plainText.Length;
            int row = (int)(Math.Ceiling(size / column));
            char[,] encrypted_matrix = new char[row, column];
            int index = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column && index < plainText.Length; j++)
                {
                    encrypted_matrix[i, j] = plainText[index];
                    index++;
                }
            }
            // key = 1 3 4 2 5
            //       0 2 3 1 4
            List<int> k = new List<int> { };
            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    if (key[j] - 1 == i)
                    {
                        k.Add(j);
                        break;
                    }
                }
            }

            string cipherText = "";
            for (int j = 0; j < column; j++)
            {
                for (int i = 0; i < row; i++)
                {
                    cipherText += encrypted_matrix[i, k[j]];
                }
            }
            return cipherText;
        }

    }
}

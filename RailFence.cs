using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            for (int i = 1; i <= plainText.Length; i++)
            {
                if (string.Compare(Encrypt(plainText, i), cipherText) == 0)
                {
                    return i;
                }

            }
            return 0;
        }

        public string Decrypt(string cipherText, int key)
        {
            double depth = key;
            double size = cipherText.Length;
            int column_length = (int)(Math.Ceiling(size / depth));
            string result = "";

            char[,] encrypted_matrix = new char[key, column_length];

            int count = 0;
            int completed_rows = cipherText.Length% key;
            bool perfect = completed_rows == 0;

            for(int i=0;i<depth;i++)
            {
                for(int j=0;j<column_length&&count<size;j++,count++)
                {
                    if(!perfect&&j==column_length-1)
                    {
                        if(completed_rows==0)
                        {
                            count--;
                            break;
                        }
                        else
                        {
                            completed_rows--;
                        }
                    }
                    encrypted_matrix[i,j] = cipherText[count];
                }
            }
            count = 0;

            for (int i = 0; i < column_length; i++)
            {
                for (int j = 0; j < depth && count < size; j++, count++)
                {
                    result+=encrypted_matrix[j, i];
                }
            }

            return result;
        }

        public string Encrypt(string plainText, int key)
        {
            double depth = key;
            double size = plainText.Length;
            int column_length = (int)(Math.Ceiling(size / depth));
            char[,] encrypted_matrix = new char[key, column_length];
            encrypt_matrix(column_length, key, encrypted_matrix, plainText);
            return encryption_result(key, column_length, encrypted_matrix);
        }

        public void encrypt_matrix(int column_length, int depth, char[,] encrypted_matrix, string plainText)
        {
            for (int j = 0, index = 0; j < column_length; j++)
            {

                for (int i = 0; i < depth && index < plainText.Length; i++, index++)
                {
                    encrypted_matrix[i, j] = plainText[index];
                }

            }
        }
        public void decrypt_matrix(int column_length, int depth, char[,] encrypted_matrix, string plainText)
        {
            int index = 0;

            for (int i = 0; i < depth; i++)
            {

                for (int j = 0; j < column_length && index < plainText.Length; j++, index++)
                {
                    // if last column should be clear
                    if(j == column_length-1&& i > (plainText.Length % depth - 1))
                    {
                        index--;
                        continue;
                    }
                    encrypted_matrix[i, j] = plainText[index];
                }

            }
        }

        public string encryption_result(int depth, int column_length, char[,] encrypted_matrix)
        {
            string result = "";
            for (int i = 0; i < depth; i++)
            {
                for (int j = 0; j < column_length; j++)
                {
                    try
                    {
                        result += encrypted_matrix[i, j];
                    }
                    catch (Exception e)
                    {
                        continue;
                    }
                }
            }
            return result;
        }

        public string decryption_result(int column_length, int depth, char[,] encrypted_matrix)
        {
            string result = "";
            for (int j = 0, index = 0; j < column_length; j++)
            {

                for (int i = 0; i < depth; i++, index++)
                {
                    result += encrypted_matrix[i, j];
                }

            }
            return result;
        }


    }
}

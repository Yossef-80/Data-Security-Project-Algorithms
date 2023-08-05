using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> result = new List<int>();
            List<int> plain = new List<int>() { plainText[0], plainText[1], plainText[2], plainText[3] };
            List<int> cipher = new List<int>() { cipherText[0], cipherText[1], cipherText[2], cipherText[3] };
            //int a = (cipher[0]-cipher[1]*plain[1]/plain[3])/(plain[0] - plain[2]*plain[1]/plain[3])% 26;
            for (int i = 0; i < 26; i++)
            {
                bool flag = false;
                for (int j = 0; j < 26; j++)
                {
                    if ((i * plain[0] + j * plain[1]) % 26 == cipher[0] &&
                        (i * plain[2] + j * plain[3]) % 26 == cipher[2])
                    {
                        result.Add(i);
                        result.Add(j);
                        flag = true;
                        break;
                    }

                }
                if (flag)
                    break;
            }

            for (int i = 0; i < 26; i++)
            {
                bool flag = false;
                for (int j = 0; j < 26; j++)
                {
                    if ((i * plain[0] + j * plain[1]) % 26 == cipher[1] &&
                        (i * plain[2] + j * plain[3]) % 26 == cipher[3])
                    {
                        result.Add(i);
                        result.Add(j);
                        flag = true;
                        break;
                    }

                }
                if (flag)
                    break;
            }
            if (result.Count == 4)
                return result;
            else
                throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        public static int[,] Matrix_transpose(int[,] matrix_3x3)
        {
            int[,] TransposedMatrix = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    TransposedMatrix[i, j] = matrix_3x3[j, i];
                }
            }
            return TransposedMatrix;
        }
        public static int det_2x2_matrix(int[,] matrix_3x3, int column_to_exclude, int row_to_exclude)
        {
            int[,] matrix_2x2 = new int[2, 2];
            int k = 0, l = 0;
            for (int i = 0; i < 3; i++)//iterate on each row
            {
                l = 0;
                for (int j = 0; j < 3; j++)//iterate on each column
                {

                    if (i == row_to_exclude || j == column_to_exclude)
                    {
                        //    Console.WriteLine("excluded matrix 3x3[" + i + "][" + j + "] : " + matrix_3x3[i, j] + "\t");
                    }

                    else
                    {
                        //  Console.WriteLine("included matrix 3x3[" + i + "][" + j + "] : " + matrix_3x3[i, j] + "\t");

                        matrix_2x2[k, l] = matrix_3x3[i, j];
                        //Console.WriteLine("matrix 2x2[" + k + "][" + l + "] : " + matrix_2x2[k, l] + "\t");
                        l++;
                    }



                    // Console.WriteLine("------") ;
                }
                if (i != row_to_exclude)
                {
                    k++;
                }

            }
            //determinant(matrix_2x2, 2);
            //Console.WriteLine("2x2 determinant: "+determinant(matrix_2x2,2));
            return determinant(matrix_2x2, 2);
        }
        public static double calculate_b(int b, int det)
        {
            if ((b * det) % 26 == 1)
            {
                return 1;
            }
            else
            {
                return 0;
            }
        }
        public static int determinant(int[,] key_matrix, int key_matrix_size)
        {
            double sum = 0;
            int determinant = 0;
            //matrix size is 2 X 2
            if (key_matrix_size == 2)
            {
                determinant = (key_matrix[0, 0] * key_matrix[1, 1]) - (key_matrix[0, 1] * key_matrix[1, 0]);
            }
            //matrix 3 X 3
            else
            {
                for (int i = 0; i < key_matrix_size; i++)
                {
                    double sign = Math.Pow(-1, i);

                    if (i == 1)
                    {
                        sum = sum + sign * (key_matrix[0, i] * ((key_matrix[1, ((i + 2) % 3)] * key_matrix[2, (i + 1) % 3]) - (key_matrix[1, (i + 1) % 3] * key_matrix[2, (i + 2) % 3])));

                    }
                    else
                    {
                        sum = sum + sign * (key_matrix[0, i] * ((key_matrix[1, (i + 1) % 3] * key_matrix[2, (i + 2) % 3]) - (key_matrix[1, ((i + 2) % 3)] * key_matrix[2, (i + 1) % 3])));

                    }

                }
                determinant = (int)sum % 26;
                if (determinant < 0)
                {
                    determinant += 26;
                }
            }

            return determinant;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            double key_matrix_size = Math.Sqrt(key.Count);
            
            int row_size = cipherText.Count / (int)key_matrix_size;
            //make matrix of key
            int[,] key_m = make_matrix((int)key_matrix_size, (int)key_matrix_size, key, false);

            int determ = determinant(key_m, (int)key_matrix_size);
            int b = 0;
            int[,] key_inverse = new int[(int)key_matrix_size, (int)key_matrix_size];
            List<int> plainText = new List<int>();
            //if the matrix 2 X 2
            if (key_matrix_size == 2)
            {
                if (1 / determ == 0)
                {
                    throw new Exception();
                }
                key_inverse[0, 0] = key_m[1, 1] * (1 / determ);
                key_inverse[0, 1] = -key_m[0, 1] * (1 / determ);
                key_inverse[1, 0] = -key_m[1, 0] * (1 / determ);
                key_inverse[1, 1] = key_m[0, 0] * (1 / determ);

                List<int> key_list = new List<int>();
                for (int i = 0; i < 2; i++)
                {
                    for (int j = 0; j < 2; j++)
                    {
                        key_list.Add(key_inverse[i, j]);
                    }
                }
                plainText = Encrypt(cipherText, key_list);
                for (int i = 0; i < plainText.Count; i++)
                {
                    plainText[i] = plainText[i] % 26;
                    if (plainText[i] < 0)
                    {
                        plainText[i] = plainText[i] + 26;
                    }
                }
            }
            else //matrix size= 3X3
            {
                for (int i = 0; i < 26; i++)
                {
                    if (calculate_b(i, determ) == 1)
                    {
                        b = i;
                        break;
                    }

                }

                int[,] k_inverse = new int[(int)key_matrix_size, (int)key_matrix_size];
                for (int i = 0; i < key_matrix_size; i++)
                {
                    for (int j = 0; j < key_matrix_size; j++)
                    {
                        double negative_1 = Math.Pow(-1, i + j);
                        key_inverse[i, j] = (b * (int)negative_1 * (det_2x2_matrix(key_m, j, i))) % 26;
                        if (key_inverse[i, j] < 0)
                        {
                            key_inverse[i, j] += 26;
                        }

                    }
                }
                int[,] transposedMatrix = Matrix_transpose(key_inverse);

                List<int> key_matrix = new List<int>();
                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        key_matrix.Add(transposedMatrix[i, j]);

                    }
                }
                plainText = Encrypt(cipherText, key_matrix);

            }


            return plainText;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            double key_matrix_size = Math.Sqrt(key.Count);
            int row_size = plainText.Count / (int)key_matrix_size;


            int[,] plain_matrix = make_matrix(row_size, (int)key_matrix_size, plainText, true);
            int[,] key_matrix = make_matrix((int) key_matrix_size,(int) key_matrix_size, key, false);

            
            return multiply_matrixes(row_size, (int)key_matrix_size, plain_matrix, key_matrix);

        }

        public static List<int> multiply_matrixes(int row_size, int key_matrix_size, int[,] plain_matrix, int[,] key_matrix)
        {
            List<int> result = new List<int>();
            int sum;
            for (int i = 0; i < row_size; i++)
            {
                for (int n = 0; n < key_matrix_size; n++)
                {
                    sum = 0;
                    for (int l = 0; l < key_matrix_size; l++)
                    {
                        sum += key_matrix[n, l] * plain_matrix[l, i];
                    }
                    sum = sum % 26;
                    result.Add(sum);
                }

            }
            return result;
        }

        public static int[,] make_matrix(int row_size, int key_matrix_size, List<int> plainText, bool plain)
        {
            int count = 0;
            int[,] arr = new int[key_matrix_size, row_size];
            for (int i = 0; i < row_size; i++)
            {
                for (int s = 0; s < key_matrix_size; s++)
                {
                    if (plain)
                    {
                        arr[s, i] = plainText[count];
                        count++;
                    }
                    else
                    {
                        arr[i, s] = plainText[count];
                        count++;
                    }
                }
            }
            return arr;
        }

        public string Encrypt(string plainText, string key)
        {
            List<int> plain = new List<int>();
            List<int> N_key = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                char c = plainText[i];
                plain.Add(c - 'a');
            }
            for (int i = 0; i < key.Length; i++)
            {
                char c = key[i];
                N_key.Add(c-'a');
            }
            List<int> cipher_integer = Encrypt(plain, N_key);
            string cipher_string = "";
            for (int i = 0; i < cipher_integer.Count; i++)
            {
                cipher_string += (char)'a' + cipher_integer[i];
            }
            return cipher_string;
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<int> result = new List<int>();
            for (int i = 0; i < 26; i++)
            {
                bool flag = false;
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        if ((i*plain3[0]+ j*plain3[1]+ k*plain3[2])%26==cipher3[0]&&
                            (i*plain3[3]+ j*plain3[4]+ k*plain3[5])%26==cipher3[3]&&
                            (i*plain3[6]+ j*plain3[7]+ k*plain3[8])%26==cipher3[6])
                        {
                            result.Add(i);
                            result.Add(j);
                            result.Add(k);
                            flag = true;
                            break;
                        }
                    }
                    if (flag)
                        break;
                }
                if (flag)
                    break;
            }

            for (int i = 0; i < 26; i++)
            {
                bool flag = false;
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        if ((i * plain3[0] + j * plain3[1] + k * plain3[2]) % 26 == cipher3[1] &&
                            (i * plain3[3] + j * plain3[4] + k * plain3[5]) % 26 == cipher3[4] &&
                            (i * plain3[6] + j * plain3[7] + k * plain3[8]) % 26 == cipher3[7])
                        {
                            result.Add(i);
                            result.Add(j);
                            result.Add(k);
                            flag = true;
                            break;
                        }
                    }
                    if (flag)
                        break;
                }
                if (flag)
                    break;
            }
            for (int i = 0; i < 26; i++)
            {
                bool flag = false;
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        if ((i * plain3[0] + j * plain3[1] + k * plain3[2]) % 26 == cipher3[2] &&
                            (i * plain3[3] + j * plain3[4] + k * plain3[5]) % 26 == cipher3[5] &&
                            (i * plain3[6] + j * plain3[7] + k * plain3[8]) % 26 == cipher3[8])
                        {
                            result.Add(i);
                            result.Add(j);
                            result.Add(k);
                            flag = true;
                            break;
                        }
                    }
                    if (flag)
                        break;
                }
                if (flag)
                    break;
            }
            return result;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
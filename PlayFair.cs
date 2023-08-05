using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            Dictionary<char, int> playFair_matrix = construct_matrix(key);
            string decrypted_text = "";

            for (int i = 0; i < cipherText.Length - 1; i += 2)
            {
                string temp = "";

                temp += cipherText[i];
                temp += cipherText[i + 1];
                decrypted_text += get_decrypted(temp, playFair_matrix);
            }
            decrypted_text = remove_x(decrypted_text);
            return decrypted_text;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            Dictionary<char, int> playFair_matrix = construct_matrix(key);
            string encrypted_text = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                string temp = "";

                if (i == plainText.Length - 1)
                {
                    temp += (plainText[i]);
                    temp += 'x';
                    encrypted_text += get_encrypted(temp, playFair_matrix);
                }
                else
                {
                    if (plainText[i] != plainText[i + 1])
                    {
                        temp += (plainText[i]);
                        temp += plainText[i + 1];
                        encrypted_text += get_encrypted(temp, playFair_matrix);
                        i += 1;
                    }
                    else
                    {
                        temp += (plainText[i]);
                        temp += 'x';
                        encrypted_text += get_encrypted(temp, playFair_matrix);
                    }
                }
            }

            // if duplicated chars in a row -> put x after first char
            // if a single char in the end  -> put x after it


            // if chars on same row     -> get next char in row  (left to right)
            // if chars on same column  -> get next char in column (top to bottom)
            // if chars on diagonals    -> get same row but opposite column


            return encrypted_text;
        }



        public string get_encrypted(string two_chars, Dictionary<char, int> playFair_matrix)
        {
            string returned_word = "";
            two_chars = two_chars.Replace('j', 'i');
            int[] index = new int[2];

            index[0] = playFair_matrix[two_chars[0]];
            index[1] = playFair_matrix[two_chars[1]];

            if (index[0] / 5 == index[1] / 5)
            {
                // same row
                returned_word += same_row(index, playFair_matrix, 4, 1);
            }

            else if (index[0] % 5 == index[1] % 5)
            {
                // same column
                returned_word += same_column(index, playFair_matrix, 4, 1);
            }


            else
            {
                // diagonal

                returned_word += get_diagonal(index, playFair_matrix);

            }
            return returned_word;
        }

        public string get_decrypted(string two_chars, Dictionary<char, int> playFair_matrix)
        {
            string returned_word = "";
            two_chars = two_chars.Replace('j', 'i');
            int[] index = new int[2];

            index[0] = playFair_matrix[two_chars[0]];
            index[1] = playFair_matrix[two_chars[1]];

            if (index[0] / 5 == index[1] / 5)
            {
                // same row
                returned_word += same_row(index, playFair_matrix, 0, -1);
            }

            else if (index[0] % 5 == index[1] % 5)
            {
                // same column
                returned_word += same_column(index, playFair_matrix, 0, -1);
            }


            else
            {
                // diagonal

                returned_word += get_diagonal(index, playFair_matrix);

            }
            return returned_word;
        }

        public char get_from_matrix(int index, Dictionary<char, int> playFair_matrix)
        {
            foreach (KeyValuePair<char, int> entry in playFair_matrix)
            {
                if (entry.Value == index)
                {
                    return entry.Key;
                }
            }

            return 'a';
        }
        public string same_row(int[] index, Dictionary<char, int> playFair_matrix, int edge_index, int ltr)
        {
            string returned_word = "";
            for (int i = 0; i < 2; i++)
            {
                if (index[i] % 5 == edge_index)
                {
                    // on the edge of row
                    returned_word += get_from_matrix(index[i] - 4 * ltr, playFair_matrix);
                }
                else
                {
                    // start or center of row
                    returned_word += get_from_matrix(index[i] + 1 * ltr, playFair_matrix);
                }
            }
            return returned_word;
        }
        public string same_column(int[] index, Dictionary<char, int> playFair_matrix, int edge_index, int ttb)
        {
            string returned_word = "";
            for (int i = 0; i < 2; i++)
            {
                if (index[i] / 5 == edge_index)
                {
                    // on the edge of column
                    returned_word += get_from_matrix(index[i] - 20 * ttb, playFair_matrix);
                }
                else
                {
                    // start or center of column
                    returned_word += get_from_matrix(index[i] + 5 * ttb, playFair_matrix);
                }
            }
            return returned_word;
        }
        public string get_diagonal(int[] index, Dictionary<char, int> playFair_matrix)
        {
            string returned_word = "";
            int index1_column = index[0] % 5;
            int index2_column = index[1] % 5;

            int index1 = index[0] - index1_column + index2_column;
            int index2 = index[1] - index2_column + index1_column;

            returned_word += get_from_matrix(index1, playFair_matrix);
            returned_word += get_from_matrix(index2, playFair_matrix);
            return returned_word;
        }

        public Dictionary<char, int> construct_matrix(string key)
        {

            Dictionary<char, int> playFair_matrix = new Dictionary<char, int>();
            // 1- construct the matrix

            // 1.1- first add the (key) to the matrix

            int index = 0; // to keep track of every character index

            for (int i = 0; i < key.Length; i++)
            {

                if (key[i] == 'i' || key[i] == 'j')
                {
                    if (!playFair_matrix.ContainsKey('i'))
                    {
                        playFair_matrix.Add('i', index);
                        index++;
                    }
                }
                else if (!playFair_matrix.ContainsKey(key[i]))
                {
                    playFair_matrix.Add(key[i], index);
                    index++;
                }

            }

            // 1.2 then add the rest of letters to matrix

            for (char c = 'a'; c <= 'z'; c++)
            {
                if (c == 'i' || c == 'j')
                {
                    if (!playFair_matrix.ContainsKey('i'))
                    {
                        playFair_matrix.Add('i', index);
                        index++;
                    }
                }

                else if (!playFair_matrix.ContainsKey(c))
                {
                    playFair_matrix.Add(c, index);
                    index++;
                }
            }
            return playFair_matrix;
        }

        public string remove_x(string decrypted_text)
        {
            for (int i = 0; i < decrypted_text.Length - 2; i += 2)
            {
                if (decrypted_text[i].Equals(decrypted_text[i + 2]))
                {
                    if (decrypted_text[i + 1] == 'x')
                    {
                        decrypted_text = decrypted_text.Remove(i + 1, 1);
                        i--;
                    }
                }
            }

            if (decrypted_text[decrypted_text.Length - 1] == 'x')
                decrypted_text = decrypted_text.Remove(decrypted_text.Length - 1, 1);

            return decrypted_text;
        }

    }
}
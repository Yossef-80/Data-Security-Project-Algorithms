using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            long K = pow(y, k, q);
            long C1;
            long C2;
            C1 = pow(alpha, k, q);
            C2 = (K * m) % q;
            List<long> list = new List<long>() { C1, C2 };
            return list;

            //alpha primitive root
            //q     prime number
            //

            throw new NotImplementedException();


        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            long K = pow(c1, x, q);
            long K_inverse = GetMultiplicativeInverse((int)K, q);
            long M = (c2 * K_inverse) % q;
            return (int)M;

        }

        public int pow(int a, int b, int c)
        {
            int res = 1, i = 0;
            while (i++ < b)
            {
                res = (res * a) % c;
            }
            return res;
        }
        public static int GetMultiplicativeInverse(int number, int baseN)
        {
            List<int> Q = new List<int>();
            List<int> A1 = new List<int>();
            List<int> A2 = new List<int>();
            List<int> A3 = new List<int>();
            List<int> B1 = new List<int>();
            List<int> B2 = new List<int>();
            List<int> B3 = new List<int>();

            Q.Add(0);
            A1.Add(1);
            A2.Add(0);
            A3.Add(baseN);
            B1.Add(0);
            B2.Add(1);
            B3.Add(number);

            int i = 1;
            while (true)
            {
                Q.Add(A3.ElementAt(i - 1) / B3.ElementAt(i - 1));
                A1.Add(B1.ElementAt(i - 1));
                A2.Add(B2.ElementAt(i - 1));
                A3.Add(B3.ElementAt(i - 1));
                B1.Add(A1.ElementAt(i - 1) - (Q.ElementAt(i) * B1.ElementAt(i - 1)));
                B2.Add(A2.ElementAt(i - 1) - (Q.ElementAt(i) * B2.ElementAt(i - 1)));
                B3.Add(A3.ElementAt(i - 1) - (Q.ElementAt(i) * B3.ElementAt(i - 1)));
                if (B3.ElementAt(i) == 0)
                {
                    return -1;
                }
                else if (B3.ElementAt(i) == 1)

                {

                    int res = B2.ElementAt(i);
                    if (B2.ElementAt(i) < 0)
                        res = B2.ElementAt(i) + baseN;
                    return res;
                }
                i++;


            }

        }
    }
}

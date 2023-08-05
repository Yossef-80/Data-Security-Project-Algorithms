using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
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
                    // Console.WriteLine("invers B2 : " + B2[i]);

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

using System.Collections.Generic;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = pow(alpha, xa, q);
            int yb = pow(alpha, xb, q);


            int k1 = pow(yb, xa, q);
            int k2 = pow(ya, xb, q);

            List<int> keys = new List<int>();

            keys.Add(k1);
            keys.Add(k2);


            return keys;

        }
        public static int pow(int b, int p, int mod)
        {
            if (p == 0) { return 1; }
            if (p == 1) { return b % mod; }
            if (p % 2 == 0)
            {
                int res = pow(b, p / 2, mod) % mod;
                return (res * res) % mod;
            }
            else
            {
                int res = pow(b, p / 2, mod) % mod;
                return ((res * res) % mod * (b % mod)) % mod;
            }
        }
    }
}

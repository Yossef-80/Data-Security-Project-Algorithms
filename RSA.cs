namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int mPOWe = pow(M, e, n);
            return mPOWe;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int phi_n = (p - 1) * (q - 1);
            int i = 0, d;
            while (true)
            {
                if ((e * i) % phi_n == 1)
                {
                    d = i;
                    break;
                }
                i++;
            }
            int cPOWd = pow(C, d, n);
            return cPOWd;
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
    }
}


using System.Security.Cryptography;
using System.Linq;
using System.Text;

namespace SecurityRemotePasswordProtocol
{
    public class Client
    {
        /// <summary>
        ///  authenticate Username
        /// </summary>
        public string username { get; protected set; }

        /// <summary>
        ///  Authenticate Password
        /// </summary>
        public string password { get; protected set; }

        /// <summary>
        /// True if the user is authenticated, false otherwise
        /// </summary>
        public bool authenticatationComplite { get; protected set; }

        public byte[] SessionKey { get { return byte_K; } }

        /// <summary>
        /// N in the SRP formula
        /// </summary>
        private BigInteger N;

        /// <summary>
        /// g in the SRP formula
        /// </summary>
        private BigInteger g;

        /// <summary>
        /// a in the SRP formula
        /// </summary>
        private BigInteger a;

        /// <summary>
        /// A in the SRP formula
        /// </summary>
        private byte[] byte_A;

        /// <summary>
        /// k in the SRP formula
        /// </summary>
        private BigInteger k;

        /// <summary>
        /// H_AMK in the SRP formula
        /// </summary>
        private byte[] H_AMK;

        /// <summary>
        /// Shared session key
        /// </summary>
        byte[] byte_K;

        /// <summary>
        /// Constructor without default values for .NET 2.0 support
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        public Client(string username, string password) : this(username, password, null, null) {}

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="username">The username to authenticate</param>
        /// <param name="password">The password to authenticate</param>
        /// <param name="byte_N">N as per the SRP formula, if not passed, a default 8096 bit N is used</param>
        /// <param name="byte_g">The corresponding generator value for N, by default, this is decimal 19</param>
        public Client(string username, string password, byte[] byte_N, byte[] byte_g)
        {
            // Set stuff
            this.username = username;
            this.password = password;
            this.authenticatationComplite = false;
            N = byte_N != null ? new BigInteger(byte_N) : Default.N;
            g = byte_g != null ? new BigInteger(byte_g) : Default.g;

            // Generate a random 32 byte a
            byte[] byte_a = new byte[32];
            RNGCryptoServiceProvider.Create().GetBytes(byte_a);
            this.a = new BigInteger(byte_a).abs();

            // Compute A
            byte_A = g.modPow(a, N).getBytes();
            
            // Compute k in byte array form
            byte[] byte_k;
            using (SHA512 h = SHA512.Create())
            {
                byte_k = h.ComputeHash(N.getBytes().Concat(g.getBytes()).ToArray());
            }

            // Get BigInteger k and store it
            this.k = new BigInteger(byte_k).abs();
        }

        /// <summary>
        /// Returns A, which is needed to start authentication.
        /// This should be sent to the verifier along with the username
        /// </summary>
        /// <returns></returns>
        public byte[] StartAuthentication()
        {
            return byte_A;
        }

        /// <summary>
        /// Returns M if the challenge was successfully processed
        /// Otherwise, null is returned
        /// </summary>
        /// <returns>M or null</returns>
        public byte[] ProcessChallenge(byte[] byte_s, byte[] byte_B)
        {
            BigInteger s = new BigInteger(byte_s).abs();
            BigInteger B = new BigInteger(byte_B).abs();

            // SRP-6a dictated safety check
            if(B % N == 0)
            {
                return null;
            }

            // Compute M
            byte[] byte_M;

            using(SHA512 h = SHA512.Create())
            {
                byte[] byte_u = h.ComputeHash(byte_A.Concat(B.getBytes()).ToArray());
            
                BigInteger u = new BigInteger(byte_u);

                // SRP-6a dictated safety check
                if(u == 0)
                {
                    return null;
                }

                // Compute x
                Encoding encoding = new ASCIIEncoding();
                byte[] byte_I = encoding.GetBytes(username);
                byte[] byte_p = encoding.GetBytes(password);
                byte[] byte_x = General.GenerateX(byte_s, byte_I, byte_p);
                BigInteger x = new BigInteger(byte_x).abs();

                // Compute v
                BigInteger v = g.modPow(x, N).abs();

                // Compute S
                // The remainder is computed here, not the modulo.
                // This means that, if n is negative, we need to do N - remainder to get the modulo
                BigInteger S = (B - k * v).modPow(a + u * x, N);

                if (S < 0)
                {
                    S = N + S;
                }

                // Compute K
                byte_K = h.ComputeHash(S.getBytes());

                // Compute M
                byte_M = General.GenerateM(N.getBytes(), g.getBytes(), byte_I, byte_s, byte_A, B.getBytes(), byte_K);

                // And finally, hash A, M and K together
                H_AMK = h.ComputeHash(byte_A.Concat(byte_M).Concat(byte_K).ToArray());
            }

            return byte_M;
        }

        /// <summary>
        /// Verify the passed server session
        /// </summary>
        /// <param name="host_H_AMK">The host's H_AMK</param>
        public void VerifySession(byte[] host_H_AMK)
        {
            if(host_H_AMK.Length != H_AMK.Length)
            {
                return;
            }

            for(int i = 0; i < H_AMK.Length; i++)
            {
                if (H_AMK[i] != host_H_AMK[i])
                {
                    return;
                }
            }

            authenticatationComplite = true;
        }
    }
}

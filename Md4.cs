using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{

    public static class Md4
    {
        [DllImport("libcrypto", EntryPoint = "MD4")]
        private static extern unsafe void* MD4(void* data, IntPtr length, void* md);

        public static unsafe void Hash(Span<byte> output, Span<byte>input)
        {
            if (output.Length < 16)
            {
                throw new InvalidOperationException("buffer too small");
            }
            
            fixed (void* data = input)
            fixed (void* md = output)
            {
                MD4(data, (IntPtr)input.Length, md);
            }
        }
    }
}

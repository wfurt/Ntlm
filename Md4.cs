using System.Reflection;
using System.Runtime.InteropServices;


namespace System.Security.Cryptography
{

    public static class Md4
    {
        const string libname = "libcrypto";

        static Md4()
        {
            NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), LoadLibcrypto);
        }

        private static IntPtr LoadLibcrypto(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
        {
            IntPtr handle = IntPtr.Zero;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                // Try to load libressl that comes with OS.
                for (int i = 40; i < 50; i++)
                {
                    if (NativeLibrary.TryLoad($"libcrypto.{i}.dylib", out handle))
                    {
                        return handle;
                    }
                }

                // fallback to OpenSSL from Brew
                if (!NativeLibrary.TryLoad("libcrypto.1.1.dylib", out handle))
                {
                    NativeLibrary.TryLoad("libcrypto.1.0.dylib", out handle);
                }
            }

            return handle;
        }

        [DllImport(libname, EntryPoint = "MD4")]
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

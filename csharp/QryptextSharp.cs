using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

namespace GlitchedPolygons.QryptextSharp
{
    /// <summary>
    /// Qryptext C# wrapper class. <para> </para>
    /// Copy this class into your own C# project and then
    /// don't forget to copy the lib/ folder to your own project's build output directory!
    /// </summary>
    public class QryptextSharpContext : IDisposable
    {
        #region Shared library loaders (per platform implementations)

        private interface ISharedLibLoadUtils
        {
            IntPtr LoadLibrary(string fileName);
            void FreeLibrary(IntPtr handle);
            IntPtr GetProcAddress(IntPtr handle, string name);
        }

        private class SharedLibLoadUtilsWindows : ISharedLibLoadUtils
        {
            [DllImport("kernel32.dll")]
            private static extern IntPtr LoadLibrary(string fileName);

            [DllImport("kernel32.dll")]
            private static extern int FreeLibrary(IntPtr handle);

            [DllImport("kernel32.dll")]
            private static extern IntPtr GetProcAddress(IntPtr handle, string procedureName);

            void ISharedLibLoadUtils.FreeLibrary(IntPtr handle)
            {
                FreeLibrary(handle);
            }

            IntPtr ISharedLibLoadUtils.GetProcAddress(IntPtr dllHandle, string name)
            {
                return GetProcAddress(dllHandle, name);
            }

            IntPtr ISharedLibLoadUtils.LoadLibrary(string fileName)
            {
                return LoadLibrary(fileName);
            }
        }

        private class SharedLibLoadUtilsLinux : ISharedLibLoadUtils
        {
            const int RTLD_NOW = 2;

            [DllImport("libdl.so")]
            private static extern IntPtr dlopen(String fileName, int flags);

            [DllImport("libdl.so")]
            private static extern IntPtr dlsym(IntPtr handle, String symbol);

            [DllImport("libdl.so")]
            private static extern int dlclose(IntPtr handle);

            [DllImport("libdl.so")]
            private static extern IntPtr dlerror();

            public IntPtr LoadLibrary(string fileName)
            {
                return dlopen(fileName, RTLD_NOW);
            }

            public void FreeLibrary(IntPtr handle)
            {
                dlclose(handle);
            }

            public IntPtr GetProcAddress(IntPtr dllHandle, string name)
            {
                dlerror();
                IntPtr res = dlsym(dllHandle, name);
                IntPtr err = dlerror();
                if (err != IntPtr.Zero)
                {
                    throw new Exception("dlsym: " + Marshal.PtrToStringAnsi(err));
                }

                return res;
            }
        }

        private class SharedLibLoadUtilsMac : ISharedLibLoadUtils
        {
            const int RTLD_NOW = 2;

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlopen(String fileName, int flags);

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlsym(IntPtr handle, String symbol);

            [DllImport("libdl.dylib")]
            private static extern int dlclose(IntPtr handle);

            [DllImport("libdl.dylib")]
            private static extern IntPtr dlerror();

            public IntPtr LoadLibrary(string fileName)
            {
                return dlopen(fileName, RTLD_NOW);
            }

            public void FreeLibrary(IntPtr handle)
            {
                dlclose(handle);
            }

            public IntPtr GetProcAddress(IntPtr dllHandle, string name)
            {
                dlerror();
                IntPtr res = dlsym(dllHandle, name);
                IntPtr err = dlerror();
                if (err != IntPtr.Zero)
                {
                    throw new Exception("dlsym: " + Marshal.PtrToStringAnsi(err));
                }

                return res;
            }
        }

        #endregion

        #region Struct mapping

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct QryptextKyber1024SecretKey
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = (3168 * 2) + 1)]
            public string hexString;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct QryptextKyber1024PublicKey
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = (1568 * 2) + 1)]
            public string hexString;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct QryptextKyber1024KeyPair
        {
            public QryptextKyber1024PublicKey publicKey;
            public QryptextKyber1024SecretKey secretKey;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct QryptextFalcon1024SecretKey
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = (2305 * 2) + 1)]
            public string hexString;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct QryptextFalcon1024PublicKey
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = (1793 * 2) + 1)]
            public string hexString;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct QryptextFalcon1024KeyPair
        {
            public QryptextFalcon1024PublicKey publicKey;
            public QryptextFalcon1024SecretKey secretKey;
        }

        #endregion

        #region Function mapping

        #region Console logging

        private delegate void EnableFprintfDelegate();

        private delegate void DisableFprintfDelegate();

        [return: MarshalAs(UnmanagedType.U1)]
        private delegate byte IsFprintfEnabledDelegate();

        #endregion

        #region Util

        private delegate void DevUrandomDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] outputArray,
            [MarshalAs(UnmanagedType.U8)] ulong outputArraySize
        );

        [return: MarshalAs(UnmanagedType.U4)]
        private delegate uint GetVersionNumberDelegate();

        private delegate IntPtr GetVersionNumberStringDelegate();

        [return: MarshalAs(UnmanagedType.U8)]
        private delegate ulong CalcEncryptionOutputLengthDelegate(
            [MarshalAs(UnmanagedType.U8)] ulong plaintextLength
        );

        [return: MarshalAs(UnmanagedType.U8)]
        private delegate ulong CalcBase64LengthDelegate(
            [MarshalAs(UnmanagedType.U8)] ulong dataLength
        );

        #endregion

        #region Key generation

        [return: MarshalAs(UnmanagedType.I4)]
        private delegate int GenerateKyber1024KeyPairDelegate(
            ref QryptextKyber1024KeyPair output
        );

        [return: MarshalAs(UnmanagedType.I4)]
        private delegate int GenerateFalcon1024KeyPairDelegate(
            ref QryptextFalcon1024KeyPair output
        );

        #endregion

        #region Encryption/Decryption

        [return: MarshalAs(UnmanagedType.I4)]
        private delegate int EncryptDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] data,
            [MarshalAs(UnmanagedType.U8)] ulong dataLength,
            [MarshalAs(UnmanagedType.LPArray)] byte[] outputBuffer,
            [MarshalAs(UnmanagedType.U8)] ulong outputBufferSize,
            out ulong outputLength,
            [MarshalAs(UnmanagedType.U1)] byte outputBase64,
            QryptextKyber1024PublicKey kyber1024PublicKey
        );

        [return: MarshalAs(UnmanagedType.I4)]
        private delegate int DecryptDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] encryptedData,
            [MarshalAs(UnmanagedType.U8)] ulong dataLength,
            [MarshalAs(UnmanagedType.U1)] byte encryptedDataBase64,
            [MarshalAs(UnmanagedType.LPArray)] byte[] outputBuffer,
            [MarshalAs(UnmanagedType.U8)] ulong outputBufferSize,
            out ulong outputLength,
            QryptextKyber1024SecretKey kyber1024SecretKey
        );

        #endregion

        #region Signing/Verifying

        [return: MarshalAs(UnmanagedType.I4)]
        private delegate int SignDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] data,
            [MarshalAs(UnmanagedType.U8)] ulong dataLength,
            [MarshalAs(UnmanagedType.LPArray)] byte[] outputBuffer,
            [MarshalAs(UnmanagedType.U8)] ulong outputBufferSize,
            out ulong outputLength,
            [MarshalAs(UnmanagedType.U1)] byte outputBase64,
            QryptextFalcon1024SecretKey falcon1024SecretKey
        );

        [return: MarshalAs(UnmanagedType.I4)]
        private delegate int VerifyDelegate(
            [MarshalAs(UnmanagedType.LPArray)] byte[] data,
            [MarshalAs(UnmanagedType.U8)] ulong dataLength,
            [MarshalAs(UnmanagedType.LPArray)] byte[] signature,
            [MarshalAs(UnmanagedType.U8)] ulong signatureLength,
            [MarshalAs(UnmanagedType.U1)] byte signatureBase64,
            QryptextFalcon1024PublicKey falcon1024PublicKey
        );

        #endregion

        #endregion

        private readonly IntPtr lib;
        private readonly ISharedLibLoadUtils loadUtils;

        private readonly EnableFprintfDelegate enableFprintfDelegate;
        private readonly DisableFprintfDelegate disableFprintfDelegate;
        private readonly IsFprintfEnabledDelegate isFprintfEnabledDelegate;
        private readonly DevUrandomDelegate devUrandomDelegate;
        private readonly GetVersionNumberDelegate getVersionNumberDelegate;
        private readonly GetVersionNumberStringDelegate getVersionNumberStringDelegate;
        private readonly CalcEncryptionOutputLengthDelegate calcEncryptionOutputLengthDelegate;
        private readonly CalcBase64LengthDelegate calcBase64LengthDelegate;
        private readonly GenerateKyber1024KeyPairDelegate generateKyber1024KeyPairDelegate;
        private readonly GenerateFalcon1024KeyPairDelegate generateFalcon1024KeyPairDelegate;
        private readonly EncryptDelegate encryptDelegate;
        private readonly DecryptDelegate decryptDelegate;
        private readonly SignDelegate signDelegate;
        private readonly VerifyDelegate verifyDelegate;

        /// <summary>
        /// Absolute path to the shared library that is currently loaded into memory for this wrapper class.
        /// </summary>
        public string LoadedLibraryPath { get; }

        /// <summary>
        /// Creates a new qryptext instance. <para> </para>
        /// Make sure to create one only once and cache it as needed, since loading the DLLs into memory can negatively affect the performance.
        /// <param name="sharedLibPathOverride">[OPTIONAL] Don't look for a <c>lib/</c> folder and directly use this path as a pre-resolved, platform-specific shared lib/DLL file path. Pass this if you want to manually handle the various platform's paths yourself.</param>
        /// </summary>
        public QryptextSharpContext(string sharedLibPathOverride = null)
        {
            string os;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                os = "windows";
                loadUtils = new SharedLibLoadUtilsWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                os = "linux";
                loadUtils = new SharedLibLoadUtilsLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                os = "mac";
                loadUtils = new SharedLibLoadUtilsMac();
            }
            else
            {
                throw new PlatformNotSupportedException("Unsupported OS");
            }

            if (string.IsNullOrEmpty(sharedLibPathOverride))
            {
                StringBuilder pathBuilder = new StringBuilder(256);
                pathBuilder.Append("lib/");

                switch (RuntimeInformation.ProcessArchitecture)
                {
                    case Architecture.X64:
                        pathBuilder.Append("x64/");
                        break;
                    case Architecture.X86:
                        pathBuilder.Append("x86/");
                        break;
                    case Architecture.Arm:
                        pathBuilder.Append("armeabi-v7a/");
                        break;
                    case Architecture.Arm64:
                        pathBuilder.Append("arm64-v8a/");
                        break;
                }

                if (!Directory.Exists(pathBuilder.ToString()))
                {
                    throw new PlatformNotSupportedException($"Qryptext shared library not found in {pathBuilder} and/or unsupported CPU architecture. Please don't forget to copy the Qryptext shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory.  https://github.com/GlitchedPolygons/qryptext/tree/master/csharp/lib/");
                }

                pathBuilder.Append(os);
                pathBuilder.Append('/');

                string[] l = Directory.GetFiles(pathBuilder.ToString());
                if (l == null || l.Length != 1)
                {
                    throw new FileLoadException("There should only be exactly one shared library file per supported platform!");
                }

                pathBuilder.Append(Path.GetFileName(l[0]));
                LoadedLibraryPath = Path.GetFullPath(pathBuilder.ToString());
                pathBuilder.Clear();
            }
            else
            {
                LoadedLibraryPath = sharedLibPathOverride;
            }

            lib = loadUtils.LoadLibrary(LoadedLibraryPath);
            if (lib == IntPtr.Zero)
            {
                goto hell;
            }


            IntPtr enableFprintf = loadUtils.GetProcAddress(lib, "qryptext_enable_fprintf");
            if (enableFprintf == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr disableFprintf = loadUtils.GetProcAddress(lib, "qryptext_disable_fprintf");
            if (disableFprintf == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr isFprintfEnabled = loadUtils.GetProcAddress(lib, "qryptext_is_fprintf_enabled");
            if (isFprintfEnabled == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr getVersionNumber = loadUtils.GetProcAddress(lib, "qryptext_get_version_number");
            if (getVersionNumber == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr getVersionNumberString = loadUtils.GetProcAddress(lib, "qryptext_get_version_number_string");
            if (getVersionNumberString == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr devUrandom = loadUtils.GetProcAddress(lib, "qryptext_dev_urandom");
            if (devUrandom == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr calcEncryptionOutputLength = loadUtils.GetProcAddress(lib, "qryptext_calc_encryption_output_length");
            if (calcEncryptionOutputLength == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr calcBase64Length = loadUtils.GetProcAddress(lib, "qryptext_calc_base64_length");
            if (calcBase64Length == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr genKyber1K = loadUtils.GetProcAddress(lib, "qryptext_kyber1024_generate_keypair");
            if (genKyber1K == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr genFalcon1K = loadUtils.GetProcAddress(lib, "qryptext_falcon1024_generate_keypair");
            if (genFalcon1K == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr encrypt = loadUtils.GetProcAddress(lib, "qryptext_encrypt");
            if (encrypt == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr decrypt = loadUtils.GetProcAddress(lib, "qryptext_decrypt");
            if (decrypt == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr sign = loadUtils.GetProcAddress(lib, "qryptext_sign");
            if (sign == IntPtr.Zero)
            {
                goto hell;
            }

            IntPtr verify = loadUtils.GetProcAddress(lib, "qryptext_verify");
            if (verify == IntPtr.Zero)
            {
                goto hell;
            }

            enableFprintfDelegate = Marshal.GetDelegateForFunctionPointer<EnableFprintfDelegate>(enableFprintf);
            disableFprintfDelegate = Marshal.GetDelegateForFunctionPointer<DisableFprintfDelegate>(disableFprintf);
            isFprintfEnabledDelegate = Marshal.GetDelegateForFunctionPointer<IsFprintfEnabledDelegate>(isFprintfEnabled);
            getVersionNumberDelegate = Marshal.GetDelegateForFunctionPointer<GetVersionNumberDelegate>(getVersionNumber);
            getVersionNumberStringDelegate = Marshal.GetDelegateForFunctionPointer<GetVersionNumberStringDelegate>(getVersionNumberString);
            devUrandomDelegate = Marshal.GetDelegateForFunctionPointer<DevUrandomDelegate>(devUrandom);
            calcEncryptionOutputLengthDelegate = Marshal.GetDelegateForFunctionPointer<CalcEncryptionOutputLengthDelegate>(calcEncryptionOutputLength);
            calcBase64LengthDelegate = Marshal.GetDelegateForFunctionPointer<CalcBase64LengthDelegate>(calcBase64Length);
            generateKyber1024KeyPairDelegate = Marshal.GetDelegateForFunctionPointer<GenerateKyber1024KeyPairDelegate>(genKyber1K);
            generateFalcon1024KeyPairDelegate = Marshal.GetDelegateForFunctionPointer<GenerateFalcon1024KeyPairDelegate>(genFalcon1K);
            encryptDelegate = Marshal.GetDelegateForFunctionPointer<EncryptDelegate>(encrypt);
            decryptDelegate = Marshal.GetDelegateForFunctionPointer<DecryptDelegate>(decrypt);
            signDelegate = Marshal.GetDelegateForFunctionPointer<SignDelegate>(sign);
            verifyDelegate = Marshal.GetDelegateForFunctionPointer<VerifyDelegate>(verify);

            return;

            hell:
            throw new Exception($"Failed to load one or more functions from the shared library \"{LoadedLibraryPath}\"!");
        }

        /// <summary>
        /// Frees unmanaged resources (unloads the shared lib/dll).
        /// </summary>
        public void Dispose()
        {
            loadUtils.FreeLibrary(lib);
        }

        private static byte[] MarshalReadBytes(IntPtr array, ulong arrayLength, int bufferSize = 1024 * 256)
        {
            using var ms = new MemoryStream((int)arrayLength);

            IntPtr i = array;
            ulong rem = arrayLength;
            byte[] buf = new byte[bufferSize];

            while (rem != 0)
            {
                int n = (int)Math.Min(rem, (ulong)buf.LongLength);
                Marshal.Copy(i, buf, 0, n);
                i = IntPtr.Add(i, n);
                rem -= (ulong)n;
                ms.Write(buf, 0, n);
            }

            return ms.ToArray();
        }

        private static byte[] TrimArray(byte[] array, ulong destlen)
        {
            if (array == null || destlen == (ulong)array.LongLength)
            {
                return array;
            }

            byte[] trimmed = new byte[destlen];
            Array.Copy(array, trimmed, trimmed.LongLength);
            return trimmed;
        }

        /// <summary>
        /// Enables qryptext's use of fprintf(). 
        /// </summary>
        public void EnableConsoleLogging()
        {
            enableFprintfDelegate();
        }

        /// <summary>
        /// Disables qryptext's use of fprintf().
        /// </summary>
        public void DisableConsoleLogging()
        {
            disableFprintfDelegate();
        }

        /// <summary>
        /// Check whether this library is allowed to fprintf() into stdout or not.
        /// </summary>
        public bool IsConsoleLoggingEnabled()
        {
            byte r = isFprintfEnabledDelegate();
            return r != 0;
        }

        /// <summary>
        /// Gets <paramref name="n"/> random bytes (on linux and mac via <c>/dev/urandom</c>, on Windows using <c>BCryptGenRandom</c>).
        /// </summary>
        /// <param name="n">How many random bytes to return?</param>
        /// <returns>An array of <paramref name="n"/> random bytes.</returns>
        public byte[] GetRandomBytes(ulong n)
        {
            byte[] o = new byte[n];
            devUrandomDelegate(o, n);
            return o;
        }

        /// <summary>
        /// Gets the current library version number (numeric).
        /// </summary>
        /// <returns>Qryptext version number (32-bit unsigned integer).</returns>
        public uint GetVersionNumber()
        {
            return getVersionNumberDelegate();
        }

        /// <summary>
        /// Gets the current library version number as a nicely-formatted, human-readable string.
        /// </summary>
        /// <returns>Library version number (MAJOR.MINOR.PATCH)</returns>
        public string GetVersionNumberString()
        {
            IntPtr str = getVersionNumberStringDelegate();
            return Marshal.PtrToStringAnsi(str);
        }

        /// <summary>
        /// Generates a Kyber1024 key pair.
        /// </summary>
        /// <returns><c>null</c> if key generation failed; a <c>(publicKey,privateKey)</c> tuple if the operation succeeded.</returns>
        public Tuple<string, string> GenerateKyber1024KeyPair()
        {
            QryptextKyber1024KeyPair kp = new QryptextKyber1024KeyPair();
            int r = generateKyber1024KeyPairDelegate(ref kp);
            if (r != 0)
            {
                return null;
            }

            return new Tuple<string, string>(kp.publicKey.hexString, kp.secretKey.hexString);
        }
        
        /// <summary>
        /// Generates a Falcon1024 key pair.
        /// </summary>
        /// <returns><c>null</c> if key generation failed; a <c>(publicKey,privateKey)</c> tuple if the operation succeeded.</returns>
        public Tuple<string, string> GenerateFalcon1024KeyPair()
        {
            QryptextFalcon1024KeyPair kp = new QryptextFalcon1024KeyPair();
            int r = generateFalcon1024KeyPairDelegate(ref kp);
            if (r != 0)
            {
                return null;
            }

            return new Tuple<string, string>(kp.publicKey.hexString, kp.secretKey.hexString);
        }

        /// <summary>
        /// Encrypts a given byte array of data using Kyber1024 + AES256-GCM.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="outputBase64">Should the encrypted output bytes be base64-encoded for easy transmission over e.g. email?</param>
        /// <param name="kyber1024PublicKey"></param>
        /// <returns>The encrypted data if encryption succeeded; <c>null</c> if something failed.</returns>
        public byte[] Encrypt(byte[] data, bool outputBase64, string kyber1024PublicKey)
        {
            ulong olen = calcEncryptionOutputLengthDelegate((ulong)data.LongLength);
            if (outputBase64)
            {
                olen = calcBase64LengthDelegate(olen);
            }

            byte[] outputBuffer = new byte[olen];
            int r = encryptDelegate(data, (ulong)data.LongLength, outputBuffer, olen, out olen, (byte)(outputBase64 ? 1 : 0), new QryptextKyber1024PublicKey { hexString = kyber1024PublicKey });
            return r != 0 ? null : TrimArray(outputBuffer, olen);
        }

        /// <summary>
        /// Decrypts a given byte array of data that was encrypted using <see cref="Encrypt"/>.
        /// </summary>
        /// <param name="encryptedData">The data to decrypt.</param>
        /// <param name="encryptedDataBase64">Is the encrypted data a base64-encoded string?</param>
        /// <param name="kyber1024SecretKey">The Kyber1024 private key with which to decrypt the data.</param>
        /// <returns>The decrypted data if decryption succeeded; <c>null</c> if something failed.</returns>
        public byte[] Decrypt(byte[] encryptedData, bool encryptedDataBase64, string kyber1024SecretKey)
        {
            ulong encryptedDataLength;
            if (encryptedData == null || (encryptedDataLength = (ulong)encryptedData.LongLength) == 0 || string.IsNullOrEmpty(kyber1024SecretKey))
            {
                throw new ArgumentException("One or more arguments are null/invalid/empty.");
            }

            byte[] outputBuffer = new byte[encryptedDataLength];
            int r = decryptDelegate(encryptedData, encryptedDataLength, (byte)(encryptedDataBase64 ? 1 : 0), outputBuffer, (ulong)outputBuffer.LongLength, out ulong olen, new QryptextKyber1024SecretKey { hexString = kyber1024SecretKey });
            return r != 0 ? null : TrimArray(outputBuffer, olen);
        }

        /// <summary>
        /// Signs a given byte array (message) using Falcon-1024 (which within OQS uses SHAKE256 hashing internally).
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="outputBase64">Should the output signature bytes be base64-encoded for you?</param>
        /// <param name="falcon1024SecretKey">The Falcon-1024 secret key to use for signing.</param>
        /// <returns>The generated signature on success; <c>null</c> if something failed.</returns>
        public byte[] Sign(byte[] data, bool outputBase64, string falcon1024SecretKey)
        {
            ulong dataLength;
            if (data == null || (dataLength = (ulong)data.LongLength) == 0 || string.IsNullOrEmpty(falcon1024SecretKey))
            {
                throw new ArgumentException("One or more arguments are null/invalid/empty.");
            }

            byte[] outputBuffer = new byte[calcBase64LengthDelegate(1330)];
            int r = signDelegate(data, dataLength, outputBuffer, (ulong)outputBuffer.LongLength, out ulong olen, (byte)(outputBase64 ? 1 : 0), new QryptextFalcon1024SecretKey { hexString = falcon1024SecretKey });
            return r != 0 ? null : TrimArray(outputBuffer, olen);
        }

        /// <summary>
        /// Verifies a data set's signature using Falcon-1024.
        /// </summary>
        /// <param name="data">The data whose signature you want to verify.</param>
        /// <param name="signature">The signature to verify. Can be raw bytes or base64-encoded string.</param>
        /// <param name="signatureBase64">Is the <paramref name="signature"/> a base64-encoded string that needs to be decoded first before verification?</param>
        /// <param name="falcon1024PublicKey">The public Falcon-1024 key with which to verify the signature.</param>
        /// <returns><c>true</c> if the signature is valid; <c>false</c> if it's invalid or verification failed otherwise (check the console output log in case you have <see cref="IsConsoleLoggingEnabled"/> set to <c>true</c>).</returns>
        public bool Verify(byte[] data, byte[] signature, bool signatureBase64, string falcon1024PublicKey)
        {
            if (data == null || data.Length == 0 || signature == null || signature.Length == 0 || string.IsNullOrEmpty(falcon1024PublicKey))
            {
                throw new ArgumentException("One or more arguments are null/invalid/empty.");
            }

            return 0 == verifyDelegate(data, (ulong)data.LongLength, signature, (ulong)signature.LongLength, (byte)(signatureBase64 ? 1 : 0), new QryptextFalcon1024PublicKey { hexString = falcon1024PublicKey });
        }
    }

    //  --------------------------------------------------------------------
    //  ------------------------------> DEMO <------------------------------
    //  --------------------------------------------------------------------

    /// <summary>
    /// Just an example console program. Don't copy this.
    /// </summary>
    internal class Example
    {
        private static void Main(string[] args)
        {
            var qryptext = new QryptextSharpContext();

            qryptext.EnableConsoleLogging();
            Console.WriteLine("Allow fprintf: " + qryptext.IsConsoleLoggingEnabled() + Environment.NewLine);

            Console.WriteLine($"Qryptext version: {qryptext.GetVersionNumberString()} ({qryptext.GetVersionNumber()})");

            byte[] rnd = qryptext.GetRandomBytes(32);
            Console.WriteLine("Here's 32 random bytes (Base64-encoded): " + Convert.ToBase64String(rnd) + Environment.NewLine);

            Tuple<string,string> kyber1024KeyPair = qryptext.GenerateKyber1024KeyPair();
            Tuple<string,string> falcon1024KeyPair = qryptext.GenerateFalcon1024KeyPair();
            
            string plaintext = "All right, Gordon, your suit should keep you comfortable through all this. The specimen will be delivered to you in a few moments. If you would be so good as to climb up and start the rotors, we can bring the Anti-Mass Spectrometer to 80% and hold it there until the carrier arrives.";
            
            byte[] ciphertext = qryptext.Encrypt(Encoding.UTF8.GetBytes(plaintext), true, kyber1024KeyPair.Item1);
            
            byte[] signature = qryptext.Sign(ciphertext, true, falcon1024KeyPair.Item2);
            
            bool validSignature = qryptext.Verify(ciphertext, signature, true, falcon1024KeyPair.Item1);
            
            Console.WriteLine($"Plaintext: {new string(plaintext.Take(64).ToArray())} [...]\n");
            Console.WriteLine($"Ciphertext: {new string(Encoding.UTF8.GetString(ciphertext).Take(64).ToArray())} [...]\n");
            Console.WriteLine($"Signature: {new string(Encoding.UTF8.GetString(signature).Take(64).ToArray())} [...]\n");
            Console.WriteLine($"Signature Valid: {validSignature}");
            
            qryptext.DisableConsoleLogging();
            Console.WriteLine("Allow fprintf: " + qryptext.IsConsoleLoggingEnabled());

            qryptext.Dispose();
        }
    }
}
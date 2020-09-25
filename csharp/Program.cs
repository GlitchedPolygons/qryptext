using System;
using System.IO;
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
        
        private readonly IntPtr lib;
        private readonly ISharedLibLoadUtils loadUtils;
        
        /// <summary>
        /// Absolute path to the shared library that is currently loaded into memory for this wrapper class.
        /// </summary>
        public string LoadedLibraryPath { get; }

        public QryptextSharpContext()
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
                throw new PlatformNotSupportedException($"Shared library not found in {pathBuilder} and/or unsupported CPU architecture. Please don't forget to copy the shared libraries/DLL into the 'lib/{{CPU_ARCHITECTURE}}/{{OS}}/{{SHARED_LIB_FILE}}' folder of your output build directory.  https://github.com/GlitchedPolygons/qryptext/tree/master/csharp");
            }

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                loadUtils = new SharedLibLoadUtilsWindows();
                pathBuilder.Append("windows/");
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                loadUtils = new SharedLibLoadUtilsLinux();
                pathBuilder.Append("linux/");
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                loadUtils = new SharedLibLoadUtilsMac();
                pathBuilder.Append("mac/");
            }
            else
            {
                throw new PlatformNotSupportedException("Unsupported OS");
            }

            string[] l = Directory.GetFiles(pathBuilder.ToString());
            if (l == null || l.Length != 1)
            {
                throw new FileLoadException("There should only be exactly one shared library file per supported platform!");
            }

            pathBuilder.Append(Path.GetFileName(l[0]));

            LoadedLibraryPath = Path.GetFullPath(pathBuilder.ToString());

            pathBuilder.Clear();

            lib = loadUtils.LoadLibrary(LoadedLibraryPath);
            if (lib == IntPtr.Zero)
            {
                goto hell;
            }

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
            Console.WriteLine("Hello World!");
        }
    }
}

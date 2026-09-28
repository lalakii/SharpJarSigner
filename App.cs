using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;

namespace cn.lalaki.SharpJarSigner
{
    public static class App
    {
        public static void Main(string[] legacyArgs)
        {
            if (legacyArgs != null)
            {
                var inputArgs = legacyArgs.SkipWhile(item => !item.Equals("sign", StringComparison.OrdinalIgnoreCase)).Skip(1).ToList();
                if (inputArgs.Count > 3)
                {
                    var assembly = Assembly.GetExecutingAssembly();
                    var assemblies = new Dictionary<string, Assembly>();
                    foreach (var name in assembly.GetManifestResourceNames())
                    {
                        var ts = new MemoryStream();
                        using (var gzip = new GZipStream(assembly.GetManifestResourceStream(name), CompressionMode.Decompress))
                        {
                            gzip.CopyTo(ts);
                            var asm = Assembly.Load(ts.ToArray());
                            var asmName = asm.GetName();
                            assemblies[asm.FullName] = asm;
                            assemblies[asmName.Name] = asm;
                            assemblies[asmName.FullName] = asm;
                            ts.SetLength(0);
                            ts.Position = 0;
                        }
                    }
                    AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException; ;
                    AppDomain.CurrentDomain.AssemblyResolve += (_, e) => CurrentDomain_AssemblyResolve(_, e, assemblies);
                    new JarSigner(inputArgs).Sign();
                    Console.WriteLine("APK signed successfully.");
                }
                else
                {
                    Help();
                }
            }
        }
        private static void Help()
        {
            Console.WriteLine();
            Console.WriteLine("  SharpJarSigner — by lalaki, i@lalaki.cn");
            Console.WriteLine();
            Console.WriteLine("  Usage:");
            Console.WriteLine();
            Console.WriteLine("\tSharpJarSigner.exe sign <certificate.pem> <private-key.pk8> <input_file> <signer-name> [-f]");
            Console.WriteLine();
            Console.WriteLine("  Arguments:");
            Console.WriteLine();
            Console.WriteLine("\t<certificate.pem>\tPath to the signing certificate");
            Console.WriteLine("\t<private-key.pk8>\tPath to the private key");
            Console.WriteLine("\t<input_file>\t\tPath to the JAR or APK file to be signed");
            Console.WriteLine("\t<signer-name>\t\tSigner name");
            Console.WriteLine("\t-f\t\t\tOptional. Overwrite the existing output file");
            Console.WriteLine();
            Console.WriteLine("  Signing scheme:");
            Console.WriteLine();
            Console.WriteLine("\tJAR signing only (APK Signature Scheme v1)");
            Console.WriteLine();
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Console.WriteLine(e.ExceptionObject);
            Environment.Exit(1);
        }

        private static Assembly CurrentDomain_AssemblyResolve(object _, ResolveEventArgs e, Dictionary<string, Assembly> assemblies) => assemblies[e.Name];
    }
}

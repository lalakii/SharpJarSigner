/*
 * Copyright (C) 2026 lalaki
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace cn.lalaki.SharpJarSigner
{
    internal class JarSigner
    {
        private const string _lineBreak = "\r\n";
        private readonly List<string> _inputArgs;
        public JarSigner(List<string> inputArgs)
        {
            _inputArgs = inputArgs;
        }

        private X509Certificate ReadX509Certs(string certFile)
        {
            return File.Exists(certFile) ? new X509CertificateParser().ReadCertificate(File.ReadAllBytes(certFile)) : null;
        }

        private Stream CreateEntry(ZipArchive archive, string entryName)
        {
            return archive.CreateEntry(entryName, CompressionLevel.Optimal).Open();
        }

        private AsymmetricKeyParameter ReadPk8PrivateKey(string pk8File)
        {
            return File.Exists(pk8File) ? PrivateKeyFactory.CreateKey(PrivateKeyInfo.GetInstance(File.ReadAllBytes(pk8File))) : null;
        }

        private bool Skip(string entryName)
        {
            return string.IsNullOrEmpty(entryName) || (entryName.StartsWith("META-INF/") && (entryName.EndsWith(".SF") || entryName.EndsWith(".RSA") || entryName.EndsWith("MANIFEST.MF")));
        }

        private void ResetToStart(Stream stream)
        {
            if (stream.CanSeek)
            {
                stream.Position = 0;
            }
        }

        private string Sha1sum(byte[] data)
        {
            using (var ms = new MemoryStream(data))
            {
                return Sha1sum(ms);
            }
        }

        private string Sha1sum(Stream stream)
        {
            var digest = new Sha1Digest();
            var buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                digest.BlockUpdate(buffer, 0, bytesRead);
            }
            var hash = new byte[digest.GetDigestSize()];
            var size = digest.GetDigestSize();
            return size == digest.DoFinal(hash, 0) ? Base64.ToBase64String(hash) : null;
        }

        private Stream SignSfFile(byte[] sfArray)
        {
            var gen = new CmsSignedDataGenerator
            {
                UseDefiniteLength = true
            };
            var x509 = ReadX509Certs(_inputArgs[0]);
            if (x509 == null)
            {
                throw new CryptographicException("Failed to load the X.509 certificate.");
            }
            else
            {
                gen.AddCertificate(x509);
                Console.WriteLine("X.509 certificate loaded successfully.");
            }
            var pk8 = ReadPk8PrivateKey(_inputArgs[1]);
            if (pk8 == null)
            {
                throw new CryptographicException("Failed to load the PKCS#8 private key.");
            }
            else
            {
                gen.AddSignerInfoGenerator(new SignerInfoGeneratorBuilder().SetDirectSignature(true).Build(new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id, pk8), x509));
                Console.WriteLine("PKCS#8 private key loaded successfully.");
            }
            return new MemoryStream(gen.Generate(new CmsProcessableByteArray(sfArray), false).GetEncoded());
        }

        public void Sign()
        {
            var jarFile = _inputArgs[2];
            var signerName = _inputArgs[3];
            var outputJarFile = Path.Combine(Path.GetDirectoryName(jarFile), $"{Path.GetFileNameWithoutExtension(jarFile)}-signed{Path.GetExtension(jarFile)}");
            if (File.Exists(outputJarFile) && (_inputArgs.Count < 5 || !_inputArgs[4].Equals("-f", StringComparison.OrdinalIgnoreCase)))
            {
                throw new IOException("File already exists. Use -F to overwrite.");
            }
            using (var apkInput = new ZipArchive(File.OpenRead(jarFile), ZipArchiveMode.Read))
            using (var apkOutput = new ZipArchive(File.Create(outputJarFile), ZipArchiveMode.Create))
            {
                var mfStream = new MemoryStream();
                var mfWriter = new StreamWriter(mfStream)
                {
                    NewLine = _lineBreak,
                    AutoFlush = true,
                };
                mfWriter.WriteLine($"Manifest-Version: 1.0{_lineBreak}");
                var tstream = new MemoryStream();
                var sfBuilder = new StringBuilder();
                var mfItemBuilder = new StringBuilder();
                foreach (var sourceEntry in apkInput.Entries.OrderBy(x => x.Name))
                {
                    var entryName = sourceEntry.FullName;
                    if (!Skip(entryName) && sourceEntry.Length > 0)
                    {
                        tstream.SetLength(0);
                        sourceEntry.Open().CopyTo(tstream);
                        ResetToStart(tstream);
                        _ = mfItemBuilder.Clear()
                            .Append($"Name: {entryName}{_lineBreak}SHA1-Digest: {Sha1sum(tstream)}{_lineBreak}{_lineBreak}");
                        mfWriter.Write(mfItemBuilder.ToString());
                        _ = sfBuilder.Append($"Name: {entryName}{_lineBreak}")
                            .Append($"SHA1-Digest: {Sha1sum(Encoding.ASCII.GetBytes(mfItemBuilder.ToString()))}{_lineBreak}{_lineBreak}");
                        ResetToStart(tstream);
                        var newEntry = CreateEntry(apkOutput, entryName);
                        tstream.CopyTo(newEntry);
                        newEntry.Dispose();
                    }
                }
                // 写入 MANIFEST.MF
                ResetToStart(mfStream);
                var mf = CreateEntry(apkOutput, "META-INF/MANIFEST.MF");
                mfStream.CopyTo(mf);
                mf.Dispose();
                // 写入 .SF
                ResetToStart(mfStream);
                _ = sfBuilder.Insert(0, $"SHA1-Digest-Manifest: {Sha1sum(mfStream)}{_lineBreak}{_lineBreak}")
                    .Insert(0, $"Signature-Version: 1.0{_lineBreak}");
                var sfStream = new MemoryStream(Encoding.ASCII.GetBytes(sfBuilder.ToString()));
                var sf = CreateEntry(apkOutput, $"META-INF/{signerName}.SF");
                sfStream.CopyTo(sf);
                sf.Dispose();
                // 写入 .RSA
                var rsa = CreateEntry(apkOutput, $"META-INF/{signerName}.RSA");
                SignSfFile(sfStream.ToArray()).CopyTo(rsa);
                rsa.Dispose();
            }
        }
    }
}

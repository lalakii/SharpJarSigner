# SharpJarSigner

[简体中文](./README.zh.md) | [English](./README.md#)

A C# command-line tool for adding v1 signatures to JAR or APK files.

[Download](https://github.com/lalakii/SharpJarSigner/releases)

[![Downloads](https://img.shields.io/github/downloads/lalakii/SharpJarSigner/total)](https://github.com/lalakii/SharpJarSigner/releases)

## Usage

```text
SharpJarSigner.exe sign <certificate.pem> <private-key.pk8> <input-file> <signer-name> [-f]
```
| Parameter | Description |
|---|---|
| `<certificate.pem>` | Certificate file path (PEM) |
| `<private-key.pk8>` | Private key file path (Unencrypted DER) |
| `<input_file>` | Path to the Jar or APK file to be signed |
| `<signer-name>` | Signer name |
| `-f` | Optional flag to overwrite an existing output file |

## License

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

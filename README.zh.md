# SharpJarSigner

[简体中文](./README.zh.md#) | [English](./README.md)

一个用于为 JAR 或 APK 文件添加 v1 签名的 C# 命令行工具。

[Download](https://github.com/lalakii/SharpJarSigner/releases)

[![Downloads](https://img.shields.io/github/downloads/lalakii/SharpJarSigner/total)](https://github.com/lalakii/SharpJarSigner/releases)

## Usage

```text
SharpJarSigner.exe sign <certificate.pem> <private-key.pk8> <input-file> <signer-name> [-f]
```
| Parameter | Description |
|---|---|
| `<certificate.pem>` | X509 证书路径 |
| `<private-key.pk8>` | 未加密的私钥路径 |
| `<input_file>` | 要签名 Jar 或 APK 路径 |
| `<signer-name>` | 签名者名称 |
| `-f` | 如果输出的文件存在强制覆盖 (可选) |

## License

[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

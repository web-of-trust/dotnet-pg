DotNet PG installation
======================

## Requirement
* .NET 9.x or later.
* [BouncyCastle.NET](https://www.bouncycastle.org/csharp) library provides cryptography algorithms.

## Installation

## Configuration

```csharp

using DotNetPG.Common;
using DotNetPG.Enum;

// Set preferred hash algorithm.
Config.PreferredHash = HashAlgorithm.Sha256;

// Set preferred symmetric algorithm.
Config.PreferredSymmetric = SymmetricAlgorithm.Aes256;

// Set preferred AEAD algorithm.
Config.PreferredAead = AeadAlgorithm.Gcm;

// Set preferred compression algorithm.
Config.PreferredCompression = CompressionAlgorithm.Uncompressed;

// Set AEAD protection.
Config.AeadProtect = true;

// Preset RFC9580.
Config.PresetRfc = PresetRfc.Rfc4880;
```

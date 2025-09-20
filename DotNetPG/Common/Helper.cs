// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Common;

using Enum;
using Type;
using System.Buffers.Binary;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     Helper class
/// </summary>
public static class Helper
{
    public const string Crlf = "\r\n";
    public const char Eol = '\n';

    public static byte[] Hkdf(
        byte[] key,
        int length,
        HashAlgorithm algorithm = HashAlgorithm.Sha256,
        byte[]? salt = null,
        byte[]? info = null
    )
    {
        var hkdf = new HkdfBytesGenerator(HashDigest(algorithm));
        hkdf.Init(new HkdfParameters(key, salt ?? [], info ?? []));
        var derivedKey = new byte[length];
        hkdf.GenerateBytes(derivedKey);
        return derivedKey;
    }

    public static byte[] ComputeChecksum(byte[] bytes)
    {
        var sum = bytes.Sum(b => b);
        return Pack16((short)(sum & 0xffff));
    }

    public static string ChunkSplit(string input, int chunkSize = 76, string separator = Crlf)
    {
        return string.Join(
            separator, input.Chunk(chunkSize).Select(chunk => new string(chunk))
        );
    }

    public static string GeneratePassword(int length = 32)
    {
        const string charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var result = new StringBuilder();
        var random = new SecureRandom();
        for (var i = 0; i < length; i++)
        {
            var index = random.Next(0, charSet.Length);
            result.Append(charSet[index]);
        }

        return result.ToString();
    }

    public static byte[] GeneratePrefix(SymmetricAlgorithm? symmetric)
    {
        var prefix = SecureRandom.GetNextBytes(new SecureRandom(), SymmetricBlockSize(symmetric));
        return
        [
            ..prefix,
            prefix[^2],
            prefix[^1]
        ];
    }

    public static string RemoveTrailingSpaces(string text)
    {
        var lines = text.Split(Eol).Select(line => line.TrimEnd(' ', '\r', '\n'))
            .Where(line => !string.IsNullOrEmpty(line));
        return string.Join(Eol, lines);
    }

    public static IString2Key String2Key(S2kType type = S2kType.Iterated)
    {
        if (type == S2kType.Simple) throw new ArgumentException("Simple type not supported.");
        var random = new SecureRandom();
        return type switch
        {
            S2kType.Argon2 => new Argon2S2K(
                SecureRandom.GetNextBytes(
                    random, Argon2S2K.SaltLegnth
                ),
                Config.Argon2Iteration,
                Config.Argon2Parallelism,
                Config.Argon2MemoryExponent
            ),
            _ => new GenericS2K(
                SecureRandom.GetNextBytes(random, GenericS2K.SaltLegnth),
                type,
                Config.PreferredHash,
                Config.S2kItCount
            )
        };
    }

    public static IBlockCipher CipherEngine(SymmetricAlgorithm? symmetric)
    {
        return symmetric switch
        {
            SymmetricAlgorithm.Aes128 or
                SymmetricAlgorithm.Aes192 or
                SymmetricAlgorithm.Aes256 => new AesEngine(),
            SymmetricAlgorithm.Blowfish => new BlowfishEngine(),
            SymmetricAlgorithm.Camellia128 or
                SymmetricAlgorithm.Camellia192 or
                SymmetricAlgorithm.Camellia256 => new CamelliaEngine(),
            SymmetricAlgorithm.Twofish => new TwofishEngine(),
            _ => throw new ArgumentException("Unsupported symmetric algorithm encountered.")
        };
    }

    public static IBlockCipherMode CfbCipherEngine(SymmetricAlgorithm? symmetric)
    {
        return new CfbBlockCipher(CipherEngine(symmetric), SymmetricBlockSize(symmetric) * 8);
    }

    public static IDigest HashDigest(HashAlgorithm? hash)
    {
        return hash switch
        {
            HashAlgorithm.Md5 => new MD5Digest(),
            HashAlgorithm.Sha1 => new Sha1Digest(),
            HashAlgorithm.Ripemd160 => new RipeMD160Digest(),
            HashAlgorithm.Sha256 => new Sha256Digest(),
            HashAlgorithm.Sha384 => new Sha384Digest(),
            HashAlgorithm.Sha512 => new Sha512Digest(),
            HashAlgorithm.Sha224 => new Sha224Digest(),
            HashAlgorithm.Sha3_256 => new Sha3Digest(),
            HashAlgorithm.Sha3_512 => new Sha3Digest(512),
            _ => throw new ArgumentException("Unsupported hash algorithm encountered.")
        };
    }

    public static BigInteger RandomBigInteger(BigInteger min, BigInteger max)
    {
        return BigIntegers.CreateRandomInRange(min, max, new SecureRandom());
    }

    public static BigInteger ReadMpi(byte[] bytes)
    {
        var bitLength = BinaryPrimitives.ReadInt16BigEndian(bytes.Take(2).ToArray());
        return BigIntegers.FromUnsignedByteArray(bytes.Skip(2).Take((bitLength + 7) >> 3).ToArray());
    }

    public static int SymmetricBlockSize(SymmetricAlgorithm? symmetric)
    {
        return symmetric switch
        {
            SymmetricAlgorithm.Aes128 => 16,
            SymmetricAlgorithm.Aes192 => 16,
            SymmetricAlgorithm.Aes256 => 16,
            SymmetricAlgorithm.Camellia128 => 16,
            SymmetricAlgorithm.Camellia192 => 16,
            SymmetricAlgorithm.Camellia256 => 16,
            SymmetricAlgorithm.Twofish => 16,
            SymmetricAlgorithm.Blowfish => 8,
            _ => 0
        };
    }

    public static int SymmetricKeySize(SymmetricAlgorithm? symmetric)
    {
        return symmetric switch
        {
            SymmetricAlgorithm.Aes128 or
                SymmetricAlgorithm.Camellia128 or
                SymmetricAlgorithm.Cast5 or
                SymmetricAlgorithm.Idea or
                SymmetricAlgorithm.Blowfish => 128,
            SymmetricAlgorithm.Aes192 or
                SymmetricAlgorithm.Camellia192 or
                SymmetricAlgorithm.TripleDes => 192,
            SymmetricAlgorithm.Aes256 or
                SymmetricAlgorithm.Camellia256 or
                SymmetricAlgorithm.Twofish => 256,
            _ => 0
        };
    }

    public static int AeadIvLength(AeadAlgorithm? aead)
    {
        return aead switch
        {
            AeadAlgorithm.Eax => 16,
            AeadAlgorithm.Ocb => 15,
            AeadAlgorithm.Gcm => 12,
            _ => 0
        };
    }

    public static byte[] Pack16(short length)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteInt16BigEndian(bytes, length);
        return bytes;
    }

    public static byte[] Pack32(int length)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, length);
        return bytes;
    }

    public static void AssertHash(HashAlgorithm? hash)
    {
        switch (hash)
        {
            case HashAlgorithm.Unknown:
            case HashAlgorithm.Md5:
            case HashAlgorithm.Sha1:
            case HashAlgorithm.Ripemd160:
                throw new ArgumentException($"{hash} hash algorithm is unsupported.");
        }
    }

    public static void AssertSymmetric(SymmetricAlgorithm? symmetric)
    {
        switch (symmetric)
        {
            case SymmetricAlgorithm.Plaintext:
            case SymmetricAlgorithm.Idea:
            case SymmetricAlgorithm.TripleDes:
            case SymmetricAlgorithm.Cast5:
                throw new ArgumentException($"{symmetric} symmetric algorithm is unsupported.");
        }
    }

    public static void AssertKeyAlgorithm(KeyAlgorithm? keyAlgorithm)
    {
        switch (keyAlgorithm)
        {
            case KeyAlgorithm.ElGamal:
            case KeyAlgorithm.Dsa:
            case KeyAlgorithm.ElGamalEncryptSign:
            case KeyAlgorithm.DiffieHellman:
            case KeyAlgorithm.AeDh:
            case KeyAlgorithm.AeDsa:
                throw new ArgumentException("Key algorithm is unsupported.");
        }
    }

    public static int HashSaltSize(HashAlgorithm? hash)
    {
        return hash switch
        {
            HashAlgorithm.Sha224 or HashAlgorithm.Sha256 or HashAlgorithm.Sha3_256 => 16,
            HashAlgorithm.Sha384 => 24,
            HashAlgorithm.Sha512 or HashAlgorithm.Sha3_512 => 32,
            _ => 0
        };
    }

    public static HashAlgorithm EcCurveHash(EcCurve? curve)
    {
        return curve switch
        {
            EcCurve.Curve25519 or EcCurve.Secp256R1 or EcCurve.BrainpoolP256R1 => HashAlgorithm.Sha256,
            EcCurve.Secp384R1 or EcCurve.BrainpoolP384R1 => HashAlgorithm.Sha384,
            EcCurve.Ed25519 or EcCurve.Secp521R1 or EcCurve.BrainpoolP512R1 => HashAlgorithm.Sha512,
            _ => HashAlgorithm.Unknown
        };
    }

    public static int HashDigestSize(HashAlgorithm? hash)
    {
        return hash switch
        {
            HashAlgorithm.Md5 => 16,
            HashAlgorithm.Sha1 or HashAlgorithm.Ripemd160 => 20,
            HashAlgorithm.Sha224 => 28,
            HashAlgorithm.Sha256 or HashAlgorithm.Sha3_256 => 32,
            HashAlgorithm.Sha384 => 48,
            HashAlgorithm.Sha512 or HashAlgorithm.Sha3_512 => 64,
            _ => 0
        };
    }
}
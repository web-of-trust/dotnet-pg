// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Common;

using Enum;
using Type;
using System.Text;
using Org.BouncyCastle.Security;

/// <summary>
///     Implementation of the string-to-key specifier
///     See RFC 9580, section 3.7.
/// </summary>
public class GenericS2K : IString2Key
{
    public const int SaltLegnth = 8;
    private const int ExpBias = 6;
    private const int DefaultItCount = 224;
    private readonly int _count;

    public GenericS2K(
        byte[] salt,
        S2kType type,
        HashAlgorithm hash = HashAlgorithm.Sha256,
        int itCount = DefaultItCount
    )
    {
        if (Type == S2kType.Argon2) throw new ArgumentException("Argon2 is not supported.");
        Salt = salt;
        Type = type;
        Hash = hash;
        ItCount = itCount;
        _count = (16 + (ItCount & 15)) << ((ItCount >> 4) + ExpBias);
    }

    public HashAlgorithm Hash { get; }

    public int ItCount { get; }

    public byte[] Salt { get; }

    public S2kType Type { get; }

    public int Length => Type switch
    {
        S2kType.Simple => 2,
        S2kType.Salted => 10,
        S2kType.Iterated => 11,
        S2kType.Argon2 => 20,
        _ => 0
    };

    public byte[] ToBytes()
    {
        return Type switch
        {
            S2kType.Simple => [(byte)Type, (byte)Hash],
            S2kType.Salted => [(byte)Type, (byte)Hash, ..Salt],
            S2kType.Iterated => [(byte)Type, (byte)Hash, ..Salt, (byte)ItCount],
            S2kType.GNU => [(byte)Type, ..Encoding.UTF8.GetBytes("GNU"), 1],
            _ => []
        };
    }

    public byte[] ProduceKey(string passphrase, int length)
    {
        return Type switch
        {
            S2kType.Simple => CalculateDigest(Encoding.UTF8.GetBytes(passphrase), length),
            S2kType.Salted => CalculateDigest([..Salt, ..Encoding.UTF8.GetBytes(passphrase)], length),
            S2kType.Iterated => CalculateDigest(Iterate([..Salt, ..Encoding.UTF8.GetBytes(passphrase)]), length),
            S2kType.GNU => CalculateDigest(Encoding.UTF8.GetBytes(passphrase), length),
            _ => []
        };
    }

    public static GenericS2K FromBytes(byte[] bytes)
    {
        var type = (S2kType)bytes[0];
        var hash = (HashAlgorithm)bytes[1];
        var salt = type switch
        {
            S2kType.Salted or S2kType.Iterated => bytes.Skip(2).Take(SaltLegnth).ToArray(),
            _ => []
        };
        var itCount = type == S2kType.Iterated ? bytes[SaltLegnth + 2] : 0;
        return new GenericS2K(salt, type, hash, itCount);
    }

    private byte[] Iterate(byte[] data)
    {
        if (data.Length == _count) return data;

        var count = (int)Math.Ceiling((double)_count / data.Length);
        var iterated = Enumerable.Repeat(data, count).SelectMany(x => x).ToArray();
        return iterated.Take(_count).ToArray();
    }

    private byte[] CalculateDigest(byte[] data, int length)
    {
        var algorithm = Hash.ToString();
        var digest = DigestUtilities.CalculateDigest(algorithm, data);
        while (digest.Length < length)
            digest =
            [
                ..digest,
                ..DigestUtilities.CalculateDigest(algorithm, [0, ..data])
            ];
        return digest.Take(length).ToArray();
    }
}
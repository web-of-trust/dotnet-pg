// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Common;

using Enum;
using Type;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
///     Implementation of the Argon2 string-to-key specifier
/// </summary>
public class Argon2S2K(
    byte[] salt,
    int iteration = 3,
    int parallelism = 1,
    int memoryExponent = 16)
    : IString2Key
{
    public const int SaltLegnth = 16;

    public S2kType Type => S2kType.Argon2;

    public byte[] Salt => salt;

    public int Length => 20;

    public byte[] ToBytes()
    {
        return [(byte)Type, ..salt, (byte)iteration, (byte)parallelism, (byte)memoryExponent];
    }

    public byte[] ProduceKey(string passphrase, int length)
    {
        var generator = new Argon2BytesGenerator();
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithSalt(salt)
            .WithIterations(iteration)
            .WithParallelism(parallelism)
            .WithMemoryPowOfTwo(memoryExponent)
            .Build();
        generator.Init(parameters);
        var result = new byte[length];
        generator.GenerateBytes(Encoding.UTF8.GetBytes(passphrase), result, 0, result.Length);
        return result;
    }

    public static Argon2S2K FromBytes(byte[] bytes)
    {
        var salt = bytes.Skip(1).Take(SaltLegnth).ToArray();
        var offset = SaltLegnth + 1;
        var iteration = bytes[offset++];
        var parallelism = bytes[offset++];
        var memoryExponent = bytes[offset];
        return new Argon2S2K(salt, iteration, parallelism, memoryExponent);
    }
}
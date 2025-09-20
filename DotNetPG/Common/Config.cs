// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Common;

using Enum;

/// <summary>
///     Config class
/// </summary>
public static class Config
{
    public const string Version = "DotNet Privacy Guard v1";
    public const string Comment = "The DotNet OpenPGP library";

    public const HashAlgorithm HkdfAlgo = HashAlgorithm.Sha256;

    public const bool AeadSupported = true;
    private const int AeadChunkSizeMin = 10;
    private const int AeadChunkSizeMax = 16;

    private static int _aeadChunkSize = 12;

    public static HashAlgorithm PreferredHash { get; set; } = HashAlgorithm.Sha1;

    public static SymmetricAlgorithm PreferredSymmetric { get; set; } = SymmetricAlgorithm.Aes256;

    public static CompressionAlgorithm PreferredCompression { get; set; } = CompressionAlgorithm.Uncompressed;

    public static AeadAlgorithm PreferredAead { get; set; } = AeadAlgorithm.Gcm;

    public static PresetRfc PresetRfc { get; set; } = PresetRfc.Rfc4880;

    public static int S2kItCount { get; set; } = 224;

    public static int Argon2Iteration { get; set; } = 3;

    public static int Argon2Parallelism { get; set; } = 4;

    public static int Argon2MemoryExponent { get; set; } = 16;

    public static bool AeadProtect { get; set; } = true;

    public static int AeadChunkSize
    {
        get => _aeadChunkSize;
        set => _aeadChunkSize = Math.Min(Math.Max(value, AeadChunkSizeMin), AeadChunkSizeMax);
    }

    public static bool ShowVersion { get; set; } = true;

    public static bool ShowComment { get; set; } = false;

    public static bool ChecksumRequired { get; set; } = false;

    public static bool AllowUnauthenticated { get; set; } = false;
}
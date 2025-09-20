// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Key algorithm enum
/// </summary>
public enum KeyAlgorithm
{
    /// <summary>
    ///     RSA (Encrypt or Sign) [HAC]
    /// </summary>
    RsaGeneral = 1,

    /// <summary>
    ///     RSA (Encrypt only) [HAC]
    /// </summary>
    RsaEncrypt = 2,

    /// <summary>
    ///     RSA (Sign only) [HAC]
    /// </summary>
    RsaSign = 3,

    /// <summary>
    ///     ElGamal (Encrypt only) [ELGAMAL] [HAC]
    /// </summary>
    ElGamal = 16,

    /// <summary>
    ///     DSA (Sign only) [FIPS186] [HAC]
    /// </summary>
    Dsa = 17,

    /// <summary>
    ///     Ec Diffie-Hellman (Encrypt only) [RFC6637]
    /// </summary>
    EcDh = 18,

    /// <summary>
    ///     Ec DSA (Sign only) [RFC6637]
    /// </summary>
    EcDsa = 19,

    /// <summary>
    ///     ElGamal encrypt & sign
    /// </summary>
    ElGamalEncryptSign = 20,

    /// <summary>
    ///     Diffie-Hellman
    /// </summary>
    DiffieHellman = 21,

    /// <summary>
    ///     EdDSA (Sign only) - deprecated by rfc9580 (replaced by `ed25519` identifier below)
    /// </summary>
    EdDsaLegacy = 22,

    /// <summary>
    ///     Reserved for AEDH
    /// </summary>
    AeDh = 23,

    /// <summary>
    ///     Reserved for AEDSA
    /// </summary>
    AeDsa = 24,

    /// <summary>
    ///     X25519 (Encrypt only)
    /// </summary>
    X25519 = 25,

    /// <summary>
    ///     X448 (Encrypt only)
    /// </summary>
    X448 = 26,

    /// <summary>
    ///     Ed25519 (Sign only)
    /// </summary>
    Ed25519 = 27,

    /// <summary>
    ///     Ed448 (Sign only)
    /// </summary>
    Ed448 = 28
}
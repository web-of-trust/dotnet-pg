// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Aead algorithm enum
/// </summary>
public enum AeadAlgorithm
{
    /// <summary>
    ///     A Conventional Authenticated-Encryption Mod
    /// </summary>
    Eax = 1,

    /// <summary>
    ///     The OCB Authenticated-Encryption Algorithm
    /// </summary>
    Ocb = 2,

    /// <summary>
    ///     Galois/Counter Mode (GCM) and GMAC
    /// </summary>
    Gcm = 3
}
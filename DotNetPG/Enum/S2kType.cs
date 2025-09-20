// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     S2k type enum
/// </summary>
public enum S2kType
{
    /// <summary>
    ///     Simple S2K directly hashes the string to produce the key data.
    /// </summary>
    Simple = 0,

    /// <summary>
    ///     Salted S2K includes a "salt" value in the S2K Specifier -- some arbitrary data --
    ///     that gets hashed along with the passphrase string to help prevent dictionary attacks.
    /// </summary>
    Salted = 1,

    /// <summary>
    ///     Iterated and Salted S2K includes both a salt and an octet count.
    ///     The salt is combined with the passphrase, and the resulting value is repeated and then hashed.
    /// </summary>
    Iterated = 3,

    /// <summary>
    ///     This S2K method hashes the passphrase using Argon2, as specified in RFC9106.
    ///     This provides memory hardness, further protecting the passphrase against brute-force attacks.
    /// </summary>
    Argon2 = 4,

    GNU = 101
}
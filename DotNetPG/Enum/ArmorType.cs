// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Armor type enum
/// </summary>
public enum ArmorType
{
    /// <summary>
    ///     Used for cleartext signed message.
    /// </summary>
    SignedMessage,

    /// <summary>
    ///     Used for signed, encrypted, or compressed files.
    /// </summary>
    Message,

    /// <summary>
    ///     Used for armoring public keys.
    /// </summary>
    PublicKey,

    /// <summary>
    ///     Used for armoring private keys.
    /// </summary>
    PrivateKey,

    /// <summary>
    ///     Used for armoring private keys.
    /// </summary>
    Signature
}
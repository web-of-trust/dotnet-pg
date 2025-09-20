// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Key flag enum
/// </summary>
public enum KeyFlag
{
    /// <summary>
    ///     This key may be used to make User ID certifications
    ///     (Signature Type IDs 0x10-0x13) or Direct Key signatures
    ///     (Signature Type ID 0x1F) over other keys.
    /// </summary>
    CertifyKeys = 0x01,

    /// <summary>
    ///     This key may be used to sign data.
    /// </summary>
    SignData = 0x02,

    /// <summary>
    ///     This key may be used to encrypt communications.
    /// </summary>
    EncryptCommunication = 0x04,

    /// <summary>
    ///     This key may be used to encrypt storage.
    /// </summary>
    EncryptStorage = 0x08,

    /// <summary>
    ///     The private component of this key may have been split by a secret-sharing mechanism.
    /// </summary>
    SplitPrivateKey = 0x10,

    /// <summary>
    ///     This key may be used for authentication.
    /// </summary>
    Authentication = 0x20,

    /// <summary>
    ///     The private component of this key may be in the possession of more than one person.
    /// </summary>
    SharedPrivateKey = 0x80
}
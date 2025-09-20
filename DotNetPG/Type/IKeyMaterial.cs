// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Key material interface.
/// </summary>
public interface IKeyMaterial
{
    /// <summary>
    ///     Get public key material
    /// </summary>
    IKeyMaterial PublicMaterial { get; }

    /// <summary>
    ///     Get key length
    /// </summary>
    int KeyLength { get; }

    /// <summary>
    ///     Return key material is valid
    /// </summary>
    bool IsValid();

    /// <summary>
    ///     Serialize key material to bytes
    /// </summary>
    byte[] ToBytes();
}
// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Public key material interface.
/// </summary>
public interface IVerifyKeyMaterial : IKeyMaterial
{
    /// <summary>
    ///     Verify a signature with message
    /// </summary>
    bool Verify(HashAlgorithm hash, byte[] message, byte[] signature);
}
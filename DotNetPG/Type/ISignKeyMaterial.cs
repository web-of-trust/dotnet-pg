// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Secret key material interface
/// </summary>
public interface ISignKeyMaterial : IKeyMaterial
{
    /// <summary>
    ///     Sign a message and return signature.
    /// </summary>
    byte[] Sign(HashAlgorithm hash, byte[] message);
}
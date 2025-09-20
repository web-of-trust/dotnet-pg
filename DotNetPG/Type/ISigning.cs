// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Signing interface.
/// </summary>
public interface ISigning
{
    /// <summary>
    ///     Get bytes for sign
    /// </summary>
    byte[] SignBytes();
}
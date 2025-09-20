// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     String-to-key interface.
/// </summary>
public interface IString2Key
{
    /// <summary>
    ///     Get S2K type
    /// </summary>
    S2kType Type { get; }

    /// <summary>
    ///     Get salt
    /// </summary>
    byte[] Salt { get; }

    /// <summary>
    ///     Get packet length
    /// </summary>
    int Length { get; }

    /// <summary>
    ///     Serialize s2k information to bytes
    /// </summary>
    byte[] ToBytes();

    /// <summary>
    ///     Produce a key using the specified passphrase and the defined hash algorithm
    /// </summary>
    byte[] ProduceKey(string passphrase, int length);
}
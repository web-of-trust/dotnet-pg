// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Signed message interface.
/// </summary>
public interface ISignedMessage : IArmorable
{
    /// <summary>
    ///     Get signature of signed message
    /// </summary>
    ISignature Signature { get; }

    /// <summary>
    ///     Verify signature of signed message
    /// </summary>
    IList<IVerification> Verify(
        IList<IKey> verificationKeys,
        DateTime? time = null
    );
}
// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Signature interface.
/// </summary>
public interface ISignature : IArmorable, IPacketContainer
{
    /// <summary>
    ///     Get signing key IDs
    /// </summary>
    IList<byte[]> SigningKeyIDs { get; }

    /// <summary>
    ///     Get verification errors
    /// </summary>
    string[] VerificationErrors { get; }

    /// <summary>
    ///     Verify signature with literal data
    /// </summary>
    IVerification[] Verify(
        IList<IKey> verificationKeys,
        ILiteralData literalData,
        DateTime? time = null
    );

    /// <summary>
    ///     Verify signature with cleartext
    /// </summary>
    IVerification[] VerifyCleartext(
        IList<IKey> verificationKeys,
        ICleartextMessage cleartext,
        DateTime? time = null
    );
}
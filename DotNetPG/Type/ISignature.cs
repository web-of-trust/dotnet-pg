// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Signature interface.
/// </summary>
public interface ISignature : IArmorable, IPacketContainer
{
    /// <summary>
    /// Signature packets
    /// </summary>
    IList<ISignaturePacket> Packets { get; }

    /// <summary>
    ///     Get signing key IDs
    /// </summary>
    IList<byte[]> SigningKeyIDs { get; }

    /// <summary>
    ///     Get verification errors
    /// </summary>
    IList<Exception> VerificationErrors { get; }

    /// <summary>
    ///     Verify signature with literal data
    /// </summary>
    IList<IVerification> Verify(
        IList<IKey> verificationKeys,
        ILiteralData literalData,
        DateTime? time = null
    );

    /// <summary>
    ///     Verify signature with cleartext
    /// </summary>
    IList<IVerification> VerifyCleartext(
        IList<IKey> verificationKeys,
        ICleartextMessage cleartext,
        DateTime? time = null
    );
}

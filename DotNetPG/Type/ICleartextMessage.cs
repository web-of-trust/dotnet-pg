// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Cleartext message interface.
/// </summary>
public interface ICleartextMessage
{
    /// <summary>
    ///     Get cleartext.
    /// </summary>
    string Text { get; }

    /// <summary>
    ///     Get normalized cleartext.
    /// </summary>
    string NormalizeText { get; }

    /// <summary>
    ///     Sign the message
    /// </summary>
    ISignedMessage Sign(
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    );

    /// <summary>
    ///     Create a detached signature for the message
    /// </summary>
    ISignature SignDetached(
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    );

    /// <summary>
    ///     Verify detached signature
    /// </summary>
    IList<IVerification> VerifyDetached(
        IList<IKey> verificationKeys,
        ISignature signature,
        DateTime? time = null
    );
}
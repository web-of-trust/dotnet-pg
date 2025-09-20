// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Literal message interface
/// </summary>
public interface ILiteralMessage
{
    /// <summary>
    ///     Get literal data
    /// </summary>
    ILiteralData LiteralData { get; }

    /// <summary>
    ///     Sign the message
    /// </summary>
    ILiteralMessage Sign(
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
    ///     Verify signature
    /// </summary>
    IList<IVerification> Verify(
        IList<IKey> verificationKeys,
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

    /// <summary>
    ///     Encrypt the message either with public keys, passwords, or both at once.
    /// </summary>
    IEncryptedMessage Encrypt(
        IList<IKey> encryptionKeys,
        IList<string> passwords,
        SymmetricAlgorithm symmetric = SymmetricAlgorithm.Aes256
    );

    /// <summary>
    ///     Compress the message (the literal and signature packets of the message)
    /// </summary>
    ILiteralMessage Compress(
        CompressionAlgorithm algorithm = CompressionAlgorithm.Uncompressed
    );
}
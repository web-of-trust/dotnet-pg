// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Verification interface.
/// </summary>
public interface IVerification
{
    /// <summary>
    ///     Get verification key ID
    /// </summary>
    byte[] KeyId { get; }

    /// <summary>
    ///     Get signature packet
    /// </summary>
    ISignaturePacket SignaturePacket { get; }

    /// <summary>
    ///     Get verification error
    /// </summary>
    string VerificationError { get; }

    /// <summary>
    ///     Is verified
    /// </summary>
    bool IsVerified { get; }

    /// <summary>
    ///     Get verification user IDs
    /// </summary>
    IList<string> UserIDs { get; }
}
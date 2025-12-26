// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Type;

/// <summary>
/// Verification class
/// </summary>
public class Verification(
    byte[] keyId,
    ISignaturePacket signaturePacket,
    string verificationError,
    bool isVerified,
    IList<string> userIDs)
    : IVerification
{
    public byte[] KeyId => keyId;

    public ISignaturePacket SignaturePacket => signaturePacket;

    public string VerificationError => verificationError;

    public bool IsVerified => isVerified;

    public IList<string> UserIDs => userIDs;
}

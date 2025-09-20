// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.Key;

using Common;
using Enum;
using Type;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

/// <summary>
///     EdDSA legacy public key material
/// </summary>
public class EdDsaLegacyPublicKeyMaterial(DerObjectIdentifier oid, BigInteger point)
    : EcPublicKeyMaterial(oid, point), IVerifyKeyMaterial
{
    public bool Verify(HashAlgorithm hash, byte[] message, byte[] signature)
    {
        var r = Helper.ReadMpi(signature);
        var length = (r.BitLength + 7) >> 3;
        var s = Helper.ReadMpi(signature.Skip(length + 2).ToArray());
        var digest = DigestUtilities.CalculateDigest(hash.ToString(), message);

        var verifier = new Ed25519Signer();
        verifier.Init(
            false,
            new Ed25519PublicKeyParameters(EncodedPoint.ToByteArrayUnsigned().Skip(1).ToArray())
        );
        verifier.BlockUpdate(digest, 0, digest.Length);
        return verifier.VerifySignature([..r.ToByteArrayUnsigned(), ..s.ToByteArrayUnsigned()]);
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static EdDsaLegacyPublicKeyMaterial FromBytes(byte[] bytes)
    {
        var length = bytes[0];
        byte[] data = [0x06, length, ..bytes.Skip(1).Take(length).ToArray()];
        return new EdDsaLegacyPublicKeyMaterial(
            DerObjectIdentifier.GetInstance(data),
            Helper.ReadMpi(bytes.Skip(length + 1).ToArray())
        );
    }
}
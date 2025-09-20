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
using Org.BouncyCastle.Utilities;

/// <summary>
///     ECDSA public key material
/// </summary>
public class EcDsaPublicKeyMaterial(DerObjectIdentifier oid, BigInteger point)
    : EcPublicKeyMaterial(oid, point), IVerifyKeyMaterial
{
    public bool Verify(HashAlgorithm hash, byte[] message, byte[] signature)
    {
        var r = Helper.ReadMpi(signature);
        var length = (r.BitLength + 7) >> 3;
        var s = Helper.ReadMpi(signature.Skip(length + 2).ToArray());
        var digest = DigestUtilities.CalculateDigest(hash.ToString(), message);

        var parameters = ECNamedDomainParameters.LookupOid(CurveOid);
        var q = parameters.Curve.DecodePoint(BigIntegers.AsUnsignedByteArray(EncodedPoint));
        var verifier = new ECDsaSigner();
        verifier.Init(false, new ECPublicKeyParameters("ECDSA", q, parameters));
        return verifier.VerifySignature(digest, r, s);
    }

    /// <summary>
    ///     Read key material from bytes
    /// </summary>
    public static EcDsaPublicKeyMaterial FromBytes(byte[] bytes)
    {
        var length = bytes[0];
        byte[] data = [0x06, length, ..bytes.Skip(1).Take(length).ToArray()];
        return new EcDsaPublicKeyMaterial(
            DerObjectIdentifier.GetInstance(data),
            Helper.ReadMpi(bytes.Skip(length + 1).ToArray())
        );
    }
}
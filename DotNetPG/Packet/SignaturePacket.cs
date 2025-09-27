// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

using Common;
using Enum;
using SubPacket;
using Type;
using System.Buffers.Binary;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

/// <summary>
///     Implementation an OpenPGP signature packet (Tag 2).
/// </summary>
public class SignaturePacket : BasePacket, ISignaturePacket
{
    public SignaturePacket(
        int version,
        SignatureType signatureType,
        KeyAlgorithm keyAlgorithm,
        HashAlgorithm hashAlgorithm,
        byte[] signedHashValue,
        byte[] salt,
        byte[] signature,
        ISubPacket[] hashedSubPackets,
        ISubPacket[] unhashedSubPackets
    ) : base(PacketType.Signature)
    {
        Version = version;
        SignatureType = signatureType;
        KeyAlgorithm = keyAlgorithm;
        HashAlgorithm = hashAlgorithm;
        SignedHashValue = signedHashValue;
        Salt = salt;
        Signature = signature;
        HashedSubpackets = hashedSubPackets;
        UnhashedSubpackets = unhashedSubPackets;

        if (version != (int)KeyVersion.V4 && version != (int)KeyVersion.V6)
            throw new ArgumentException("Version of the signature packet is unsupported.");

        Helper.AssertKeyAlgorithm(keyAlgorithm);
        Helper.AssertHash(hashAlgorithm);

        var isV6 = Version == (int)KeyVersion.V6;
        if (isV6)
        {
            var saltSize = Helper.HashSaltSize(hashAlgorithm);
            if (salt.Length != saltSize)
                throw new ArgumentException(
                    $"Salt size must be {saltSize} bytes."
                );
        }

        SignatureData =
        [
            (byte)Version,
            (byte)SignatureType,
            (byte)KeyAlgorithm,
            (byte)HashAlgorithm,
            ..SubPacketsToBytes(HashedSubpackets, isV6)
        ];
    }

    public int Version { get; }

    public SignatureType SignatureType { get; }

    public KeyAlgorithm KeyAlgorithm { get; }

    public HashAlgorithm HashAlgorithm { get; }

    public ISubPacket[] HashedSubpackets { get; }

    public ISubPacket[] UnhashedSubpackets { get; }

    public byte[] SignatureData { get; }

    public byte[] SignedHashValue { get; }

    public byte[] Salt { get; }

    public byte[] Signature { get; }

    public DateTime? CreationTime => GetSubPacket<SignatureCreationTime>()?.CreationTime;

    public DateTime? ExpirationTime => GetSubPacket<SignatureExpirationTime>()?.ExpirationTime;

    public int KeyExpirationTime => GetSubPacket<KeyExpirationTime>()?.ExpirationTime ?? 0;

    public byte[] IssuerKeyId => GetSubPacket<IssuerKeyId>()?.KeyId ??
                                 IssuerFingerprint.Skip(Version == (int)KeyVersion.V6 ? 0 : 12)
                                     .Take(PublicKey.KeyIdSize).ToArray();

    public byte[] IssuerFingerprint => GetSubPacket<IssuerFingerprint>()?.KeyFingerprint ??
                                       SubPacket.IssuerFingerprint.Wildcard().KeyFingerprint;

    public bool IsPrimaryUserId => GetSubPacket<PrimaryUserId>()?.IsPrimaryUserId ?? false;

    public bool IsCertification
    {
        get
        {
            switch (SignatureType)
            {
                case SignatureType.CertGeneric:
                case SignatureType.CertPersona:
                case SignatureType.CertCasual:
                case SignatureType.CertPositive:
                    return true;
                default:
                    return false;
            }
        }
    }

    public bool IsCertRevocation => SignatureType == SignatureType.CertRevocation;

    public bool IsDirectKey => SignatureType == SignatureType.DirectKey;

    public bool IsKeyRevocation => SignatureType == SignatureType.KeyRevocation;

    public bool IsSubkeyBinding => SignatureType == SignatureType.SubkeyBinding;

    public bool IsSubkeyRevocation => SignatureType == SignatureType.SubkeyRevocation;

    public T? GetSubPacket<T>() where T : ISubPacket
    {
        var subPacket = HashedSubpackets.OfType<T>().FirstOrDefault();
        if (subPacket == null) subPacket = UnhashedSubpackets.OfType<T>().FirstOrDefault();

        return subPacket;
    }

    public bool IsExpired(DateTime? time = null)
    {
        var now = DateTime.Now;
        var timestamp = new DateTimeOffset(time ?? now).ToUnixTimeSeconds();
        var creation = new DateTimeOffset(CreationTime ?? DateTime.UnixEpoch).ToUnixTimeSeconds();
        var expiration = new DateTimeOffset(ExpirationTime ?? now).ToUnixTimeSeconds();
        return !(creation <= timestamp && timestamp <= expiration);
    }

    public bool Verify(
        IKeyPacket verifyKey,
        byte[] dataToVerify,
        DateTime? time = null
    )
    {
        if (!Arrays.AreEqual(verifyKey.KeyId, IssuerKeyId))
        {
            throw new Exception("Signature was not issued by the given public key.");
        }

        if (verifyKey.KeyAlgorithm != KeyAlgorithm)
            throw new Exception(
                "Public key algorithm used to sign signature does not match issuer key algorithm."
            );

        if (IsExpired(time)) throw new Exception("Signature is expired.");

        byte[] message =
        [
            ..Salt,
            ..dataToVerify,
            ..SignatureData,
            ..CalculateTrailer(Version, SignatureData.Length)
        ];
        var hash = DigestUtilities.CalculateDigest(HashAlgorithm.ToString(), message);
        if (!Arrays.AreEqual(hash.Take(2).ToArray(), SignedHashValue))
        {
            throw new Exception("Signed digest mismatch!");
        }

        if (verifyKey.KeyMaterial is IVerifyKeyMaterial km) return km.Verify(HashAlgorithm, message, Signature);
        throw new Exception("Key material is not verifiable.");
    }

    public override byte[] ToBytes()
    {
        var isV6 = Version == (int)KeyVersion.V6;
        return
        [
            ..SignatureData,
            ..SubPacketsToBytes(UnhashedSubpackets, isV6),
            ..SignedHashValue,
            ..isV6 ? [(byte)Salt.Length, ..Salt] : Array.Empty<byte>(),
            ..Signature
        ];
    }

    /// <summary>
    ///     Read signature packet from bytes
    /// </summary>
    public static SignaturePacket FromBytes(byte[] bytes)
    {
        var offset = 0;

        // A one-octet version number.
        var version = bytes[offset++];
        var isV6 = version == (int)KeyVersion.V6;

        // One-octet signature type.
        var signatureType = (SignatureType)bytes[offset++];

        // One-octet public-key algorithm.
        var keyAlgorithm = (KeyAlgorithm)bytes[offset++];

        // One-octet hash algorithm.
        var hashAlgorithm = (HashAlgorithm)bytes[offset++];

        // Read hashed subpackets
        var hashedLength = isV6
            ? BinaryPrimitives.ReadInt32BigEndian(bytes.Skip(offset).Take(4).ToArray())
            : BinaryPrimitives.ReadInt16BigEndian(bytes.Skip(offset).Take(2).ToArray());
        offset += isV6 ? 4 : 2;
        var hashedSubpackets = SubPacketReader.ReadSignatureSubPackets(
            bytes.Skip(offset).Take(hashedLength).ToArray()
        );
        offset += hashedLength;

        // read unhashed subpackets
        var unhashedLength= isV6
            ? BinaryPrimitives.ReadInt32BigEndian(bytes.Skip(offset).Take(4).ToArray())
            : BinaryPrimitives.ReadInt16BigEndian(bytes.Skip(offset).Take(2).ToArray());
        offset += isV6 ? 4 : 2;
        var unhashedSubpackets = SubPacketReader.ReadSignatureSubPackets(
            bytes.Skip(offset).Take(unhashedLength).ToArray()
        );
        offset += unhashedLength;

        // Two-octet field holding left 16 bits of signed hash value.
        var signedHashValue = bytes.Skip(offset).Take(2).ToArray();
        offset += 2;

        byte[] salt = [];
        if (isV6)
        {
            var saltLength = bytes[offset++];
            salt = bytes.Skip(offset).Take(saltLength).ToArray();
            offset += saltLength;
        }

        var signature = bytes.Skip(offset).ToArray();

        return new SignaturePacket(
            version,
            signatureType,
            keyAlgorithm,
            hashAlgorithm,
            signedHashValue,
            salt,
            signature,
            hashedSubpackets,
            unhashedSubpackets
        );
    }

    /// <summary>
    ///     Create signature
    /// </summary>
    public static SignaturePacket CreateSignature(
        ISecretKeyPacket signKey,
        SignatureType signatureType,
        byte[] dataToSign,
        HashAlgorithm hashAlgorithm = HashAlgorithm.Sha256,
        ISubPacket[]? subPackets = null,
        DateTime? time = null
    )
    {
        var version = signKey.Version;
        var keyAlgorithm = signKey.KeyAlgorithm;
        var hashAlg = signKey.GetPreferredHash(hashAlgorithm);
        Helper.AssertHash(hashAlg);

        IList<ISubPacket> hashedSubpackets =
        [
            SignatureCreationTime.FromTime(time ?? DateTime.Now),
            SubPacket.IssuerFingerprint.FromKeyPacket(signKey),
            new IssuerKeyId(signKey.KeyId),
            ..subPackets ?? []
        ];
        var isV6 = version == (int)KeyVersion.V6;
        var saltSize = Helper.HashSaltSize(hashAlg);
        byte[] salt = [];
        if (isV6)
            salt = SecureRandom.GetNextBytes(new SecureRandom(), saltSize);
        else
            hashedSubpackets.Add(NotationData.FromNotation(
                NotationData.SaltNotaion,
                Helper.GeneratePassword(saltSize)
            ));

        byte[] signatureData =
        [
            (byte)version,
            (byte)signatureType,
            (byte)keyAlgorithm,
            (byte)hashAlg,
            ..SubPacketsToBytes(hashedSubpackets.ToArray(), isV6)
        ];
        byte[] message =
        [
            ..salt,
            ..dataToSign,
            ..signatureData,
            ..CalculateTrailer(version, signatureData.Length)
        ];
        var signedHashValue = DigestUtilities.CalculateDigest(hashAlg.ToString(), message).Take(2).ToArray();
        return new SignaturePacket(
            version,
            signatureType,
            keyAlgorithm,
            hashAlg,
            signedHashValue,
            salt,
            SignMessage(signKey, hashAlg, message),
            hashedSubpackets.ToArray(),
            []
        );
    }

    private static byte[] SignMessage(ISecretKeyPacket signKey, HashAlgorithm hash, byte[] message)
    {
        if (signKey.SecretKeyMaterial is ISignKeyMaterial km) return km.Sign(hash, message);
        throw new Exception("Invalid key material for signing.");
    }

    private static IList<ISubPacket> KeySignatureProperties(int version)
    {
        IList<ISubPacket> subPackets = [
            KeyFlags.FromFlags(
                (int)KeyFlag.CertifyKeys | (int)KeyFlag.SignData
            ),
            new PreferredSymmetricAlgorithms(
                [(int)SymmetricAlgorithm.Aes256, (int)SymmetricAlgorithm.Aes128]
            ),
            new PreferredAeadAlgorithms(
                [(int)AeadAlgorithm.Ocb, (int)AeadAlgorithm.Gcm, (int)AeadAlgorithm.Eax]
            ),
            new PreferredHashAlgorithms(
                [
                    (int)HashAlgorithm.Sha256,
                    (int)HashAlgorithm.Sha3_256,
                    (int) HashAlgorithm.Sha512,
                    (int)HashAlgorithm.Sha3_512,
                ]
            ),
            new PreferredCompressionAlgorithms(
                [
                    (int)CompressionAlgorithm.Uncompressed,
                    (int)CompressionAlgorithm.Zip,
                    (int)CompressionAlgorithm.Zlib,
                    (int)CompressionAlgorithm.BZip2,
                ]
            ),
            Features.FromFeatures(
                (int)SupportFeature.Version1Seipd | (int)SupportFeature.Version2Seipd
            ),
        ];
        if (version == (int)KeyVersion.V6)
        {
            subPackets.Add(new PreferredAeadCiphers(
                [
                    (int)SymmetricAlgorithm.Aes256, (int)AeadAlgorithm.Ocb,
                    (int)SymmetricAlgorithm.Aes256, (int)AeadAlgorithm.Gcm,
                    (int)SymmetricAlgorithm.Aes128, (int)AeadAlgorithm.Ocb,
                    (int)SymmetricAlgorithm.Aes128, (int)AeadAlgorithm.Gcm,
                    (int)SymmetricAlgorithm.Aes128, (int)AeadAlgorithm.Eax,
                ]
            ));
        }
        return subPackets;
    }
    
    private static byte[] CalculateTrailer(int version, int dataLength)
    {
        return
        [
            (byte)version, 0xff, ..Helper.Pack32(dataLength)
        ];
    }

    private static byte[] SubPacketsToBytes(
        ISubPacket[] subPackets,
        bool isV6 = false
    )
    {
        var bytes = subPackets.SelectMany(subPacket => subPacket.ToBytes()).ToArray();
        return
        [
            ..isV6 ? Helper.Pack32(bytes.Length) : Helper.Pack16((short)bytes.Length),
            ..bytes
        ];
    }
}
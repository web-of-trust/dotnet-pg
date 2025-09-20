using System.Text;
using DotNetPG.Enum;
using DotNetPG.Packet;
using DotNetPG.Packet.SubPacket;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace DotNetPG.Test.Packet;

public class SigningTest
{
    private const string LiteralText = "Hello, world!";

    private const string RsaPublicKeyData = @"BGjOBpABCADA7vjTulZQ01ji3qT22GUVGpcCYunMiKy++814g8seYuYC3hif2fq/0y4sVcVXDQhc
HGLU0zJjX/pXlBBvWPpTFBcCcpcLp0InKxh7SuP89veryNvXdbmpCsUkfMPZ9DZYQMvLaDYiglbh
05/ZNAnlpuHYy2rj3M1N42dNUugNpJO8PncjNeRfgGJEjCGRretBE5pDitdMp2ovC2up97Nf+eVl
C3MhVOdvx41JvqavKkLKRqbB74jNnzcPweNxPP/okKlhDxYGOQumxkgKd0VVdlxFVITlAPuFH3HP
UI7xrvtVVjsKEfT3GkacIhlQUeV+GPQzYb4kzs5xF4h052tvABEBAAE=";

    private const string RsaSecretKeyData = @"BGjOBpABCADA7vjTulZQ01ji3qT22GUVGpcCYunMiKy++814g8seYuYC3hif2fq/0y4sVcVXDQhc
HGLU0zJjX/pXlBBvWPpTFBcCcpcLp0InKxh7SuP89veryNvXdbmpCsUkfMPZ9DZYQMvLaDYiglbh
05/ZNAnlpuHYy2rj3M1N42dNUugNpJO8PncjNeRfgGJEjCGRretBE5pDitdMp2ovC2up97Nf+eVl
C3MhVOdvx41JvqavKkLKRqbB74jNnzcPweNxPP/okKlhDxYGOQumxkgKd0VVdlxFVITlAPuFH3HP
UI7xrvtVVjsKEfT3GkacIhlQUeV+GPQzYb4kzs5xF4h052tvABEBAAEAB/sFtfn0kamLalSEhqQD
nVBeQw0hDqd7NlJ5GfMxJyMkitEVjAujjUXwVqjUh1Q4XIdL637IOPL4lEQED24H6O5wwuf5dEXg
6O1uD/o0cBLDXDx+WVg0jpeiMTjrq973Ce6jE+vt+rw1FX5krQ+oU/OB2KI+LHgSBALc7g3GCqqA
XzqSe+pFl68ggL083a3fDfXDHL+JnvQC3U4F+dYsRHApPxu6oThlDNxwcogpr9TscNwUBi4exRy5
emuAOLeiW3K5C67SvBeCKCPSyn4dpWXVar/P5JWMKr0a5xMRpfrYD7E9n715dfMKyn8acRuOOiiW
dQqiNKdNuT4+fzv7af+xBAD+aNFWILNWQ/eNvceaAv6IYtYKjzd/gegsX7jxpzL09OU+XPK4LBjL
CJ/9m0Tm/TPxnDVzKPvoimgblKMm/kpExuETPWK28Pe8s0aQYVodVh1jOXqpzn9N2sO2jLoDQvwd
a5l0TNBQ5FPdySWt2+RzTmPwXYX+JipDhF8TutVwXwQAwiPDEhwhXCJISy0OJfAf1PS9PqD7CmDv
WDE7kvpp5RzUQanyI+1gIDByBy/lGfaWI1m2tPhK4ePqxJ2gbK3fhPlG+0MhxoZANzg81hz29HMi
6njDPqmSH/62ohP8DfdyTxxmyas2rJfN7qiY5EPBuwC8l0z44wIYFTFik1YinvEEAJWEHBrc2rBP
EElxsYYZutQISMVogtgOkq7tvCAcrHLENmqgH6+sa1+KhUQvZA68gt2PeiklbMzeZQINyNwsKEg4
DKqi3aMZupsCRdi80J+cZMhi2Ov3I4SCceK3isv3ZFPvR3eelPaObWnTaJtQjCOxy5gWBYPqGUXJ
OUs5djslQKM=";

    private const string EcDsaSecp521PublicKeyData = @"BGjOJAwTBSuBBAAjBCMEAZIhtu5SI8jsUOMWDw4vk9kRig6idReGb/u9HOG2SyRETiYQYhdOJijF
LFAayBXRjFltl3uMeYpCPZ9ch4O+NaNJANeqFNxpuZSI/7+lTPow/tzVojJPGVmRiknTccYd1lC+
DQ0iHsUVsX0BBk+gAUOK+S94FGvz4rVQvs4ARmCvMGQw";

    private const string EcDsaSecp521SecretKeyData = @"BGjOJAwTBSuBBAAjBCMEAZIhtu5SI8jsUOMWDw4vk9kRig6idReGb/u9HOG2SyRETiYQYhdOJijF
LFAayBXRjFltl3uMeYpCPZ9ch4O+NaNJANeqFNxpuZSI/7+lTPow/tzVojJPGVmRiknTccYd1lC+
DQ0iHsUVsX0BBk+gAUOK+S94FGvz4rVQvs4ARmCvMGQwAAIJATgcLU5BdnGqXqHPEWC1L4oMkDNK
cFPnCkaqxUQdOeN2dPf5lBCQAuAxj4K/QhI5OnqVk+gVGeoVqFlsXl4rSrWsG8c=";

    private const string EcDsaBrainpoolPublicKeyData = @"BGjOJ10TCSskAwMCCAEBDQQDBAFbXV5mdJjLlHAouN2jyk6qc9wtg1mKoU52cdO5lhvr0AcFUELl
yVimNEuQH4BtdQHDcGgsoXiwWs1ohHarRzlKRbr6rznGCWhNlNq3JDT4Ci5cc1jri1bkH332mW+k
Od+gOWZK445QYFqsAuGaClSuB3mIUGwIbo4ivlA7oQmt";

    private const string EcDsaBrainpoolSecretKeyData = @"BGjOJ10TCSskAwMCCAEBDQQDBAFbXV5mdJjLlHAouN2jyk6qc9wtg1mKoU52cdO5lhvr0AcFUELl
yVimNEuQH4BtdQHDcGgsoXiwWs1ohHarRzlKRbr6rznGCWhNlNq3JDT4Ci5cc1jri1bkH332mW+k
Od+gOWZK445QYFqsAuGaClSuB3mIUGwIbo4ivlA7oQmtAAIAmN5HxRMvwMeza9UXTjv6OY9JZfCN
Cm1bJU6ag46/obtIHa2VyWKyXzWUxCGslcjx1EGi8lv5B2ZmRpoZCtqUEh+2";

    private const string EdDsaLegacyPublicKeyData = @"BGjOT1wWCSsGAQQB2kcPAQEHQFFv29cNO3HUo+iSGFBvETe/4aMcOprtx1QseAcZgIvQ";

    private const string EdDsaLegacySecretKeyData = @"BGjOT1wWCSsGAQQB2kcPAQEHQFFv29cNO3HUo+iSGFBvETe/4aMcOprtx1QseAcZgIvQAAEAiwH7
2ejD8whwSmQc2urvSCTfjmsmguP6QdjcVxulOnUReA==";

    private const string Ed25519PublicKeyData = @"BmjOUKwbAAAAIGXzliozSLgNQ2GeqC7xjJFKuA54oyrj5rh53KsIN4Kg";

    private const string Ed25519SecretKeyData = @"BmjOUKwbAAAAIGXzliozSLgNQ2GeqC7xjJFKuA54oyrj5rh53KsIN4KgAC75Egs820y2v6nIfm4W
E4KkNdKjDrHw9kNAONAmujpq";

    private const string Ed448PublicKeyData = @"BmjOWIIcAAAAOXAerEENouxS0mR0TmUF40Q5yGWZ43DRYh8N45AAJU4tsx6rcIGSQ8Q4R+GNgFC8
/LDJb5aFLyVRgA==";

    private const string Ed448SecretKeyData = @"BmjOWIIcAAAAOXAerEENouxS0mR0TmUF40Q5yGWZ43DRYh8N45AAJU4tsx6rcIGSQ8Q4R+GNgFC8
/LDJb5aFLyVRgAAfcj8nzCoMn1H3Y9iM/JS2d1/ATDSM5WMW7Xt+iGj68+t1S+2zAEQKe8prRj24
dS17b/mr7Ac8HTA=";

    [Test]
    public void TestVerifyRsaSignature()
    {
        const string signatureData = @"BAIBCABVBQJozgaQFiEEa/k9N1WK4G/z2CpqreHoq6nDvq0JEK3h6Kupw76tLRQAAAAAABQAEHNh
bHRAcGhwLW9wZW5wZ3Aub3Jn+KKyAmPHByZgZ9oFEvzxBwAAkQIIAEyKVfqc2WEOshnROUwEhj43
liakrQB5PRTaQay+IOVbIf3ZtHVA9+mQkJOZfLHMJ+hq5GKYzORW1KMFcYFS6gJ6BaLQyWjfzefb
4Hk3ze7kDc2yN2KcIl53mIdZKts/oMSqhAJMgbSwWEPNkmvck6Jwkj18fSlcZrL2BZjwQDxKrb0d
SOi/nnSCKFBWLlVc0PhW+J8TTu3E5hq8KALacXKuUITYyMtT6nqIVj8Hzyc4QJTrAM0vbv1M3Bf0
jnVzDPVg4Kn4i2bomhBWJbxG/1EhIuGdhD6gTzlU4om54YypUvAzxZ8APBGRLyA8fF2drhsboQeW
CxhKwgvaXqBVc1k=";

        var publicKey = PublicKey.FromBytes(Base64.Decode(RsaPublicKeyData));
        var signature = SignaturePacket.FromBytes(Base64.Decode(signatureData));
        Assert.That(signature.Verify(publicKey, Encoding.UTF8.GetBytes(LiteralText)), Is.True);
    }

    [Test]
    public void TestRsaSigning()
    {
        var message = SecureRandom.GetNextBytes(new SecureRandom(), 1024);
        var publicKey = PublicKey.FromBytes(Base64.Decode(RsaPublicKeyData));
        var secretKey = SecretKey.FromBytes(Base64.Decode(RsaSecretKeyData));
        var signature = SignaturePacket.CreateSignature(secretKey, SignatureType.Standalone, message);
        var cloneSignature = SignaturePacket.FromBytes(signature.ToBytes());
        Assert.That(cloneSignature.Verify(publicKey, message), Is.True);
    }

    [Test]
    public void TestVerifyEcDsaSecp521Signature()
    {
        const string signatureData = @"BAITCgBlBQJoziQMFiEETUoyJp4ytVZCg1DeesudCZeAH3QJEHrLnQmXgB90PRQAAAAAABQAIHNh
bHRAcGhwLW9wZW5wZ3Aub3JniGEYdhX/4deJjrGPC1J9jbvNMjC0+OXH/cnCqtKfFjAAALBvAgkB
FzhUr+egZ1HndvHNN8WEkM02PkNdmQiKDNU55WmmbopKVjRXXZF0dEmDcRob/bmFXCnHpDKxLV+v
ueX7/nm3FKwCCQFHl+aU00dn4L8m1oCLMjMOt0WoyNJG5IQidmRLOs6A39r/1nkiLW+nOizhYNJ3
hozI/7xVTHfzJf5ZYfXzkM5ugA==";

        var publicKey = PublicKey.FromBytes(Base64.Decode(EcDsaSecp521PublicKeyData));
        var signature = SignaturePacket.FromBytes(Base64.Decode(signatureData));
        Assert.That(signature.Verify(publicKey, Encoding.UTF8.GetBytes(LiteralText)), Is.True);
    }

    [Test]
    public void TestEcDsaSecp521Signing()
    {
        var message = SecureRandom.GetNextBytes(new SecureRandom(), 1024);
        var publicKey = PublicKey.FromBytes(Base64.Decode(EcDsaSecp521PublicKeyData));
        var secretKey = SecretKey.FromBytes(Base64.Decode(EcDsaSecp521SecretKeyData));
        var signature = SignaturePacket.CreateSignature(secretKey, SignatureType.Standalone, message);
        var cloneSignature = SignaturePacket.FromBytes(signature.ToBytes());
        Assert.That(cloneSignature.Verify(publicKey, message), Is.True);
    }

    [Test]
    public void TestVerifyEcDsaBrainpoolSignature()
    {
        const string signatureData = @"BAITCgBlBQJoziddFiEEoWkM62QOOZfr8G//54UzykiZOr0JEOeFM8pImTq9PRQAAAAAABQAIHNh
bHRAcGhwLW9wZW5wZ3Aub3JnF3kc7qfhrXErUCwjZIMybxOCw3sz3gHnJQgd0Keen7sAAMIbAf4l
9yjp1hHHz6QVfzvS04y2qRI/x8uaipBHQmqMP1Moboa8DEgdFkGpM1kcNMf+F+iBIsu7AI98KK4H
zj5oWT3wAfoC4TeKg941XePea8ZhWIKDPfX1cmtUGF0EoQqFaQec0eMDwxjBGmqecD2X2zlWZAcl
47nRf4tTNUjp2VJXSO6T";

        var publicKey = PublicKey.FromBytes(Base64.Decode(EcDsaBrainpoolPublicKeyData));
        var signature = SignaturePacket.FromBytes(Base64.Decode(signatureData));
        Assert.That(signature.Verify(publicKey, Encoding.UTF8.GetBytes(LiteralText)), Is.True);
    }

    [Test]
    public void TestEcDsaBrainpoolSigning()
    {
        var message = SecureRandom.GetNextBytes(new SecureRandom(), 1024);
        var publicKey = PublicKey.FromBytes(Base64.Decode(EcDsaBrainpoolPublicKeyData));
        var secretKey = SecretKey.FromBytes(Base64.Decode(EcDsaBrainpoolSecretKeyData));
        var signature = SignaturePacket.CreateSignature(secretKey, SignatureType.Standalone, message);
        var cloneSignature = SignaturePacket.FromBytes(signature.ToBytes());
        Assert.That(cloneSignature.Verify(publicKey, message), Is.True);
    }

    [Test]
    public void TestVerifyEdDsaLegacySignature()
    {
        const string signatureData = @"BAIWCgBlBQJozk9cFiEE/OqTkovO0iT4E9G3FhOh7KBZ9pIJEBYToeygWfaSPRQAAAAAABQAIHNh
bHRAcGhwLW9wZW5wZ3Aub3JnosvImUtnSCCMBJrnxeVJZ2F8/5c8aST/dZ+2bcZW6YgAACpLAQBs
oX+IzA8MvlThDtj9+9jonSmJT7nC9Mdr/q+3lXPBIwEA35FJE5vEyn4t9HatcEvFEbOn9Xui+WjX
mw6Xz83aCQM=";

        var publicKey = PublicKey.FromBytes(Base64.Decode(EdDsaLegacyPublicKeyData));
        var signature = SignaturePacket.FromBytes(Base64.Decode(signatureData));
        Assert.That(signature.Verify(publicKey, Encoding.UTF8.GetBytes(LiteralText)), Is.True);
    }

    [Test]
    public void TestEdDsaLegacySigning()
    {
        var message = SecureRandom.GetNextBytes(new SecureRandom(), 1024);
        var publicKey = PublicKey.FromBytes(Base64.Decode(EdDsaLegacyPublicKeyData));
        var secretKey = SecretKey.FromBytes(Base64.Decode(EdDsaLegacySecretKeyData));
        var signature = SignaturePacket.CreateSignature(secretKey, SignatureType.Standalone, message);
        var cloneSignature = SignaturePacket.FromBytes(signature.ToBytes());
        Assert.That(cloneSignature.Verify(publicKey, message), Is.True);
    }

    [Test]
    public void TestVerifyEd25519Signature()
    {
        const string signatureData = @"BgIbCAAAADMFAmjOUKwiIQZU9oZ0twg8hH5EtTNjxSEV3WIT13aALtuoeaHRdA7kCwkQVPaGdLcI
PIQAAAAAGZsQ6Lv2tOSGfRfb6JAtNjy87riA8NF1z+AZwOEm10epOhPneDGEfBmRj/sXHYMDzNpe
vg916fBw/tYDyYL2Oa+SM90qGCBpbSevO1ao8t8lpQw=";

        var publicKey = PublicKey.FromBytes(Base64.Decode(Ed25519PublicKeyData));
        var signature = SignaturePacket.FromBytes(Base64.Decode(signatureData));
        Assert.That(signature.Verify(publicKey, Encoding.UTF8.GetBytes(LiteralText)), Is.True);
    }

    [Test]
    public void TestEd25519Signing()
    {
        var message = SecureRandom.GetNextBytes(new SecureRandom(), 1024);
        var publicKey = PublicKey.FromBytes(Base64.Decode(Ed25519PublicKeyData));
        var secretKey = SecretKey.FromBytes(Base64.Decode(Ed25519SecretKeyData));
        var signature = SignaturePacket.CreateSignature(secretKey, SignatureType.Standalone, message);
        var cloneSignature = SignaturePacket.FromBytes(signature.ToBytes());
        Assert.That(cloneSignature.Verify(publicKey, message), Is.True);
    }

    [Test]
    public void TestVerifyEd448Signature()
    {
        const string signatureData = @"BgIcCgAAADMFAmjOWIIiIQYPr+FUHmVR7T0Om7a629IKcJ/A+Ani7iJqJ6o8bWUuDgkQD6/hVB5l
Ue0AAAAAloUgCrVcvVyWrlowToaLYEg1bNJ1iDvNtlWznfFd7u3y+1tqZZiqxVtSL3t/3n69ksFm
0WSuE3PEwF/Q+tvNFS8x+gQYUfbVFtOs8uHk0xgbweW6w49LoEJwpQCTT0eKrDKwOZS5YIu6WFeJ
pY4NBzv/oGYJYimi25fsO1XCMHUw2DiQtgYhZ2DAeatNvekX/YvAEQA=";

        var publicKey = PublicKey.FromBytes(Base64.Decode(Ed448PublicKeyData));
        var signature = SignaturePacket.FromBytes(Base64.Decode(signatureData));
        Assert.That(signature.Verify(publicKey, Encoding.UTF8.GetBytes(LiteralText)), Is.True);
    }

    [Test]
    public void TestEd448Signing()
    {
        var message = SecureRandom.GetNextBytes(new SecureRandom(), 1024);
        var publicKey = PublicKey.FromBytes(Base64.Decode(Ed448PublicKeyData));
        var secretKey = SecretKey.FromBytes(Base64.Decode(Ed448SecretKeyData));
        var signature = SignaturePacket.CreateSignature(secretKey, SignatureType.Standalone, message);
        var cloneSignature = SignaturePacket.FromBytes(signature.ToBytes());
        Assert.That(cloneSignature.Verify(publicKey, message), Is.True);
    }

    [Test]
    public void TestFeatures()
    {
        var features = Features.FromFeatures(
            (int)SupportFeature.Version1Seipd | (int)SupportFeature.AeadEncrypted | (int)SupportFeature.Version2Seipd
        );
        Assert.Multiple(() =>
        {
            Assert.That(features.SupportV1Seipd, Is.True);
            Assert.That(features.SupportAead, Is.True);
            Assert.That(features.SupportV2Seipd, Is.True);
        });
    }

    [Test]
    public void TestKeyFlag()
    {
        var keyFlags = KeyFlags.FromFlags(
            (int)KeyFlag.CertifyKeys | (int)KeyFlag.SignData | (int)KeyFlag.EncryptCommunication | (int)KeyFlag.EncryptStorage
        );
        Assert.Multiple(() =>
        {
            Assert.That(keyFlags.IsCertifyKeys, Is.True);
            Assert.That(keyFlags.IsSignData, Is.True);
            Assert.That(keyFlags.IsEncryptCommunication, Is.True);
            Assert.That(keyFlags.IsEncryptStorage, Is.True);
        });
    }
}

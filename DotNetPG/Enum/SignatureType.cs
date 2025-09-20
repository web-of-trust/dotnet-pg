// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Signature type enum
/// </summary>
public enum SignatureType
{
    /// <summary>
    ///     Binary Signature of a Document.
    ///     This means the signer owns it, created it, or certifies that it has not been modified.
    /// </summary>
    Binary = 0x00,

    /// <summary>
    ///     Text Signature of a Canonical Document.
    ///     Canonicalyzing the document by converting line endings.
    /// </summary>
    Text = 0x01,

    /// <summary>
    ///     Standalone Signature.
    ///     This signature is a signature of only its own subpacket contents.
    ///     It is calculated identically to a signature over a zero-length binary document.
    ///     Version 3 Standalone signatures MUST NOT be generated and MUST be ignored.
    /// </summary>
    Standalone = 0x02,

    /// <summary>
    ///     Generic Certification Signature of a User ID and Public Key Packet.
    ///     The issuer of this certification does not make any particular assertion
    ///     as to how well the certifier has checked that the owner of the key is
    ///     in fact the person described by the User ID
    /// </summary>
    CertGeneric = 0x10,

    /// <summary>
    ///     Persona Certification Signature of a User ID and Public Key Packet.
    ///     The issuer of this certification has not done any verification of
    ///     the claim that the owner of this key is the User ID specified.
    /// </summary>
    CertPersona = 0x11,

    /// <summary>
    ///     Casual Certification Signature of a User ID and Public Key Packet.
    ///     The issuer of this certification has done some casual verification of the claim of identity.
    /// </summary>
    CertCasual = 0x12,

    /// <summary>
    ///     Positive Certification Signature of a User ID and Public Key Packet.
    ///     The issuer of this certification has done substantial verification of the claim of identity.
    ///     Most OpenPGP implementations make their "key signatures" as generic (Type ID 0x10) certifications.
    ///     Some implementations can issue 0x11-0x13 certifications, but few differentiate between the types.
    /// </summary>
    CertPositive = 0x13,

    /// <summary>
    ///     Subkey Binding Signature.
    ///     This signature is a statement by the top-level signing key, indicating that it owns the subkey.
    ///     This signature is calculated directly on the primary key and subkey, and not on any User ID or other packets.
    ///     A signature that binds a signing subkey MUST have an Embedded Signature subpacket in this binding signature
    ///     that contains a 0x19 signature made by the signing subkey on the primary key and subkey.
    /// </summary>
    SubkeyBinding = 0x18,

    /// <summary>
    ///     Primary Key Binding Signature.
    ///     This signature is a statement by a signing subkey, indicating that it is owned by the primary key.
    ///     This signature is calculated the same way as a Subkey Binding signature (Type ID 0x18):
    ///     directly on the primary key and subkey, and not on any User ID or other packets.
    /// </summary>
    KeyBinding = 0x19,

    /// <summary>
    ///     Direct Key Signature.
    ///     This signature is calculated directly on a key. It binds the information
    ///     in the Signature subpackets to the key and is appropriate to be used for
    ///     subpackets that provide information about the key, such as the Key Flags
    ///     subpacket or the (deprecated) Revocation Key subpacket. It is also appropriate
    ///     for statements that non-self certifiers want to make about the key itself rather
    ///     than the binding between a key and a name.
    /// </summary>
    DirectKey = 0x1f,

    /// <summary>
    ///     Key Revocation Signature.
    ///     This signature is calculated directly on the key being revoked.
    ///     A revoked key is not to be used. Only Revocation Signatures by
    ///     the key being revoked, or by a (deprecated) Revocation Key,
    ///     should be considered valid Revocation Signatures.
    /// </summary>
    KeyRevocation = 0x20,

    /// <summary>
    ///     Subkey Revocation Signature.
    ///     This signature is calculated directly on the primary key and the subkey being revoked.
    ///     A revoked subkey is not to be used. Only Revocation Signatures by the top-level signature key
    ///     that is bound to this subkey, or by a (deprecated) Revocation Key,
    ///     should be considered valid Revocation Signatures.
    /// </summary>
    SubkeyRevocation = 0x28,

    /// <summary>
    ///     Certification Revocation Signature.
    ///     This signature revokes an earlier User ID certification signature
    ///     (Type IDs 0x10 through 0x13) or Direct Key signature (Type ID 0x1F).
    ///     It should be issued by the same key that issued the revoked signature
    ///     or by a (deprecated) Revocation Key. The signature is computed over
    ///     the same data as the certification that it revokes, and it should have
    ///     a later creation date than that certification.
    /// </summary>
    CertRevocation = 0x30,

    /// <summary>
    ///     Timestamp Signature.
    ///     This signature is only meaningful for the timestamp contained in it.
    /// </summary>
    Timestamp = 0x40,

    /// <summary>
    ///     Third-Party Confirmation Signature.
    ///     This signature is a signature over another OpenPGP Signature packet.
    ///     It is analogous to a notary seal on the signed data.
    ///     A Third-Party Confirmation signature SHOULD include a Signature Target
    ///     subpacket that identifies the confirmed signature.
    /// </summary>
    ThirdParty = 0x50,

    /// <summary>
    ///     Reserved.
    /// </summary>
    Reserved = 0xff
}
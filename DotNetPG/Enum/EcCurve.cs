// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Elliptic curve enum
/// </summary>
public enum EcCurve
{
    Secp256R1,
    Secp384R1,
    Secp521R1,
    BrainpoolP256R1,
    BrainpoolP384R1,
    BrainpoolP512R1,
    Ed25519,
    Curve25519
}
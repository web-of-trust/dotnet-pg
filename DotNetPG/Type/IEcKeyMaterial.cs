// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Elliptic curve key material interface.
/// </summary>
public interface IEcKeyMaterial : IKeyMaterial
{
    /// <summary>
    ///     Get elliptic curve enum
    /// </summary>
    EcCurve Curve { get; }
}
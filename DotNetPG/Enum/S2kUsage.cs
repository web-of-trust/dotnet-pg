// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     S2k usage enum
///     S2k usage indicating whether and how the secret key material is protected by a passphrase
/// </summary>
public enum S2kUsage
{
    None = 0,
    AeadProtect = 253,
    Cfb = 254,
    MalleableCfb = 255
}
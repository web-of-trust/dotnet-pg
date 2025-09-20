// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Enum;

/// <summary>
///     Reason for revocation enum
/// </summary>
public enum RevocationReasonTag
{
    /// <summary>
    ///     reason specified (key revocations or cert revocations)
    /// </summary>
    NoReason = 0,

    /// <summary>
    ///     Key is superseded (key revocations)
    /// </summary>
    KeySuperseded = 1,

    /// <summary>
    ///     Key material has been compromised (key revocations)
    /// </summary>
    KeyCompromised = 2,

    /// <summary>
    ///     Key is retired and no longer used (key revocations)
    /// </summary>
    KeyRetired = 3,

    /// <summary>
    ///     User ID information is no longer valid (cert revocations)
    /// </summary>
    UserIdInvalid = 32
}
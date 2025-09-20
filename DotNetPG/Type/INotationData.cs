// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Notation data interface.
/// </summary>
public interface INotationData
{
    /// <summary>
    ///     Get notation name
    /// </summary>
    string NotationName { get; }

    /// <summary>
    ///     Get notation value
    /// </summary>
    string NotationValue { get; }

    /// <summary>
    ///     Is human-readable
    /// </summary>
    bool IsHumanReadable { get; }
}
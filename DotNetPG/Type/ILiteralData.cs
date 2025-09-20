// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
///     Literal data interface
/// </summary>
public interface ILiteralData : ISigning
{
    /// <summary>
    ///     Get literal format
    /// </summary>
    LiteralFormat Format { get; }

    /// <summary>
    ///     Get filename
    /// </summary>
    string Filename { get; }

    /// <summary>
    ///     Get time
    /// </summary>
    DateTime Time { get; }

    /// <summary>
    ///     Get data
    /// </summary>
    byte[] Data { get; }

    /// <summary>
    ///     Get header
    /// </summary>
    byte[] Header { get; }
}
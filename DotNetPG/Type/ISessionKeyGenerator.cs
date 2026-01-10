// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
/// Session key generator interface
/// </summary>
public interface ISessionKeyGenerator
{
    /// <summary>
    /// Generate a new session key object.
    /// </summary>
    ISessionKey Generate();
}
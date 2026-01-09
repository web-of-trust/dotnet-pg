// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

using Enum;

/// <summary>
/// OpenPGP key pair generator interface
/// </summary>
public interface IKeyGenerator
{
    IKeyGenerator WithUserIds(IList<string> userIds);

    IKeyGenerator WithPassphrase(string passphrase);

    IKeyGenerator WithKeyType(KeyType keyType);

    IKeyGenerator WithRsaKeySize(RsaKeySize keySize);

    IKeyGenerator WithEcCurve(EcCurve curve);

    IKeyGenerator WithKeyExpiry(int keyExpiry);

    IKeyGenerator WithSignOnly(bool signOnly);

    /// <summary>
    /// Generate a new OpenPGP key pair.
    /// </summary>
    IPrivateKey Generate(DateTime? time = null);
}

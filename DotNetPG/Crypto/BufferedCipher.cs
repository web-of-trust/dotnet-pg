// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Crypto;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;

/// <summary>
///     Buffered cipher.
/// </summary>
public sealed class BufferedCipher(IBlockCipherMode cipherMode) : BufferedBlockCipher(cipherMode)
{
    public byte[] Process(byte[] input)
    {
        var output = new byte[input.Length];
        DoFinal(output, ProcessBytes(
            input, 0, input.Length, output, 0
        ));
        return output;
    }
}
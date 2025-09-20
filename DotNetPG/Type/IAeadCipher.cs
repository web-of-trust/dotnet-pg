// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Type;

/// <summary>
///     Aead cipher interface.
/// </summary>
public interface IAeadCipher
{
    /// <summary>
    ///     Encrypt plain text input.
    /// </summary>
    /// <param name="plainText">The plain text input to be encrypted</param>
    /// <param name="nonce">The nonce</param>
    /// <param name="aData">Associated data to sign</param>
    /// <returns>The cipher text output.</returns>
    byte[] Encrypt(byte[] plainText, byte[] nonce, byte[] aData);

    /// <summary>
    ///     Decrypt cipher text input.
    /// </summary>
    /// <param name="cipherText">The cipher text input to be decrypted</param>
    /// <param name="nonce">The nonce</param>
    /// <param name="aData">Associated data to verify</param>
    /// <returns>The plain text output.</returns>
    byte[] Decrypt(byte[] cipherText, byte[] nonce, byte[] aData);

    /// <summary>
    ///     Get aead nonce
    /// </summary>
    /// <param name="iv">The initialization vector</param>
    /// <param name="chunkIndex">The chunk index</param>
    byte[] GetNonce(byte[] iv, byte[] chunkIndex);
}
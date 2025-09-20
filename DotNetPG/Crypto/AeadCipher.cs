// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Crypto;

using Common;
using Enum;
using IAeadCipher = Type.IAeadCipher;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

/// <summary>
///     Aead cipher class.
/// </summary>
public class AeadCipher(byte[] key, AeadAlgorithm aead, SymmetricAlgorithm symmetric)
    : IAeadCipher
{
    public byte[] Encrypt(byte[] plainText, byte[] nonce, byte[] associatedText)
    {
        var cipher = InitCipher(nonce, associatedText, true);
        return Process(cipher, plainText);
    }

    public byte[] Decrypt(byte[] cipherText, byte[] nonce, byte[] associatedText)
    {
        var cipher = InitCipher(nonce, associatedText, false);
        return Process(cipher, cipherText);
    }

    public byte[] GetNonce(byte[] iv, byte[] chunkIndex)
    {
        var nonce = (byte[])iv.Clone();
        switch (aead)
        {
            case AeadAlgorithm.Eax:
                for (var i = 0; i < chunkIndex.Length; i++) nonce[8 + i] ^= chunkIndex[i];
                break;
            case AeadAlgorithm.Gcm:
                for (var i = 0; i < chunkIndex.Length; i++) nonce[4 + i] ^= chunkIndex[i];
                break;
            case AeadAlgorithm.Ocb:
                for (var i = 0; i < chunkIndex.Length; i++) nonce[7 + i] ^= chunkIndex[i];
                break;
        }

        return nonce;
    }

    private static byte[] Process(IAeadBlockCipher cipher, byte[] input)
    {
        var output = new byte[cipher.GetOutputSize(input.Length)];
        cipher.DoFinal(output, cipher.ProcessBytes(
            input, 0, input.Length, output, 0
        ));
        return output;
    }

    private IAeadBlockCipher InitCipher(
        byte[] nonce, byte[] associatedText, bool forEncryption
    )
    {
        IAeadBlockCipher cipher = aead switch
        {
            AeadAlgorithm.Eax => new EaxBlockCipher(Helper.CipherEngine(symmetric)),
            AeadAlgorithm.Ocb => new OcbBlockCipher(
                Helper.CipherEngine(symmetric),
                Helper.CipherEngine(symmetric)
            ),
            _ => new GcmBlockCipher(Helper.CipherEngine(symmetric))
        };
        cipher.Init(
            forEncryption,
            new AeadParameters(
                new KeyParameter(key),
                Helper.SymmetricBlockSize(symmetric) * 8,
                nonce,
                associatedText
            )
        );
        return cipher;
    }
}
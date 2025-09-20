// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet.SubPacket;

using Enum;

/// <summary>
///     PreferredAeadCiphers sub-packet class
/// </summary>
public class PreferredAeadCiphers(byte[] data, bool critical = false)
    : SignatureSubPacket((int)SignatureSubPacketType.PreferredAeadCiphers, data, critical)
{
    public AeadAlgorithm[] PreferredAeads(SymmetricAlgorithm symmetric)
    {
        var aeads = new List<AeadAlgorithm>();
        var data = Data;
        while (data.Length > 0)
        {
            var ciphers = data.Take(2).ToArray();
            data = data.Skip(2).ToArray();
            if (ciphers.Length == 2)
            {
                var preferred = (SymmetricAlgorithm)ciphers[0];
                if (symmetric == preferred) aeads.Add((AeadAlgorithm)ciphers[1]);
            }
        }

        return aeads.ToArray();
    }
}
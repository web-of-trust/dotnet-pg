// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Message;

using Type;

/// <summary>
/// OpenPGP encrypted message class
/// </summary>
public class EncryptedMessage(IPacketList packetList) : BaseMessage(packetList), IEncryptedMessage
{
    public IEncryptedDataPacket EncryptedPacket { get; }
    public ISessionKey? SessionKey { get; }
    public ILiteralMessage Decrypt(IList<IKey> decryptionKeys, IList<string> passwords)
    {
        throw new NotImplementedException();
    }
}

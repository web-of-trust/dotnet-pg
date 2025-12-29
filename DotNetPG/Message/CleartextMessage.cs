// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

using System.Text.RegularExpressions;

namespace DotNetPG.Message;

using Common;
using Packet;
using Type;

/// <summary>
/// Class that represents an OpenPGP cleartext message.
/// </summary>
public class CleartextMessage(string text) : ICleartextMessage
{
    private readonly string _text = Helper.RemoveTrailingSpaces(text);

    public string Text => Regex.Replace(_text, "\r?\n", "\r\n", RegexOptions.Multiline);

    public string NormalizeText => Regex.Replace(_text, "\r\n", "\n", RegexOptions.Multiline);

    public ISignedMessage Sign(
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
     )
    {
        return new SignedMessage(
            Text,
            SignDetached(signingKeys, recipients, notationData, time)
        );
    }

    public ISignature SignDetached(
        IList<IPrivateKey> signingKeys,
        IList<IKey>? recipients = null,
        INotationData? notationData = null,
        DateTime? time = null
    )
    {
        if (signingKeys.Count == 0)
        {
            throw new ArgumentException("No signing keys provided.");
        }

        var signatures = signingKeys.Select(
            key => SignaturePacket.CreateLiteralData(
                key.SecretKeyPacket,
                LiteralData.FromText(Text),
                recipients ?? [],
                notationData,
                time
            )
        );
        return new Signature([..signatures]);
    }

    public IList<IVerification> VerifyDetached(
        IList<IKey> verificationKeys,
        ISignature signature,
        DateTime? time = null
    )
    {
        return signature.VerifyCleartext(verificationKeys, this, time);
    }
}
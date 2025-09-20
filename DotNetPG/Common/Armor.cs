// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Common;

using Enum;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Utilities.Encoders;

/// <summary>
///     Class that represents an OpenPGP Base64 Conversions.
///     See RFC 9580, section 6.
/// </summary>
public sealed class Armor(ArmorType type, byte[] data, string[] header, string text = "")
{
    private const string MessageBegin = "-----BEGIN PGP MESSAGE-----\n";
    private const string SignedMessageBegin = "-----BEGIN PGP SIGNED MESSAGE-----\n";
    private const string MessageEnd = "-----END PGP MESSAGE-----\n";

    private const string PublicKeyBlockBegin = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
    private const string PublicKeyBlockEnd = "-----END PGP PUBLIC KEY BLOCK-----\n";

    private const string PrivateKeyBlockBegin = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n";
    private const string PrivateKeyBlockEnd = "-----END PGP PRIVATE KEY BLOCK-----\n";

    private const string SignatureBegin = "-----BEGIN PGP SIGNATURE-----\n";
    private const string SignatureEnd = "-----END PGP SIGNATURE-----\n";

    private const string DashPattern = @"^- ";
    private const string EmptyPattern = @"(^[\r\n]*|[\r\n]+)[\s\t]*[\r\n]+";
    private const string HeaderPattern = @"^([^\s:]|[^\s:][^:]*[^\s:]): .+$";
    private const string SplitPattern = @"^-----[^-]+-----$";

    private const string BeginPattern =
        @"^-----BEGIN PGP (SIGNED MESSAGE|MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$";

    public ArmorType Type => type;

    public byte[] Data => data;

    public string[] Header => header;

    public string Text => text;

    /// <summary>
    ///     Dearmor an OpenPGP armored message.
    /// </summary>
    public static Armor Decode(string armoredText)
    {
        var textDone = false;
        var checksum = "";
        ArmorType? type = null;

        var headers = new List<string>();
        var textLines = new List<string>();
        var dataLines = new List<string>();

        var lines = armoredText.Split(Helper.Eol);
        foreach (var line in lines)
        {
            // Remove trailing spaces
            var trimedline = line.TrimEnd(' ', '\r', '\n');
            if (type == null && Regex.IsMatch(trimedline, SplitPattern))
            {
                type = ParseArmorType(trimedline);
            }
            else
            {
                if (Regex.IsMatch(trimedline, HeaderPattern))
                {
                    headers.Add(trimedline);
                }
                else if (!textDone && type == ArmorType.SignedMessage)
                {
                    if (!Regex.IsMatch(trimedline, SplitPattern))
                    {
                        textLines.Add(Regex.Replace(trimedline, DashPattern, string.Empty));
                    }
                    else
                    {
                        textDone = true;
                        // Remove first empty line (not included in the message digest)
                        textLines.RemoveAt(0);
                    }
                }
                else if (!Regex.IsMatch(trimedline, SplitPattern))
                {
                    if (Regex.IsMatch(trimedline, EmptyPattern)) continue;

                    if (trimedline.StartsWith('='))
                        checksum = trimedline.Substring(1);
                    else
                        dataLines.Add(trimedline);
                }
            }
        }

        var text = string.Join(Helper.Crlf, textLines);
        var data = Base64.Decode(string.Join("", dataLines));

        if (checksum == Crc24Checksum(data) &&
            (!string.IsNullOrEmpty(checksum) || Config.ChecksumRequired))
            throw new Exception("Ascii armor integrity check failed.");

        return new Armor(
            type ?? ArmorType.Message, data, headers.ToArray(), text
        );
    }

    /// <summary>
    ///     Armor an OpenPGP binary packet block
    /// </summary>
    public static string Encode(
        ArmorType type,
        byte[] data,
        string[] hashAlgos,
        string text = "",
        string customComment = ""
    )
    {
        var sb = new StringBuilder();
        switch (type)
        {
            case ArmorType.SignedMessage:
                sb.Append(SignedMessageBegin);
                var hashHeaders = string.Join(
                    Helper.Eol, hashAlgos.Select(hash => $"Hash: {hash}")
                );
                if (!string.IsNullOrEmpty(hashHeaders)) sb.Append(hashHeaders).Append("\n\n");
                sb.Append(Regex.Replace(
                    text, DashPattern, "- -", RegexOptions.Multiline
                )).Append(Helper.Eol);
                sb.Append(SignatureBegin);
                sb.Append(AddHeader(customComment)).Append(Helper.Eol);
                sb.Append(Base64Encode(data)).Append(Helper.Eol);
                if (Config.ChecksumRequired) sb.Append(Crc24Checksum(data)).Append(Helper.Eol);
                sb.Append(SignatureEnd);
                break;
            case ArmorType.Message:
                sb.Append(MessageBegin);
                sb.Append(AddHeader(customComment)).Append(Helper.Eol);
                sb.Append(Base64Encode(data)).Append(Helper.Eol);
                if (Config.ChecksumRequired) sb.Append('=').Append(Crc24Checksum(data)).Append(Helper.Eol);
                sb.Append(MessageEnd);
                break;
            case ArmorType.PublicKey:
                sb.Append(PublicKeyBlockBegin);
                sb.Append(AddHeader(customComment)).Append(Helper.Eol);
                sb.Append(Base64Encode(data)).Append(Helper.Eol);
                if (Config.ChecksumRequired) sb.Append(Crc24Checksum(data)).Append(Helper.Eol);
                sb.Append(PublicKeyBlockEnd);
                break;
            case ArmorType.PrivateKey:
                sb.Append(PrivateKeyBlockBegin);
                sb.Append(AddHeader(customComment)).Append(Helper.Eol);
                sb.Append(Base64Encode(data)).Append(Helper.Eol);
                if (Config.ChecksumRequired) sb.Append(Crc24Checksum(data)).Append(Helper.Eol);
                sb.Append(PrivateKeyBlockEnd);
                break;
            case ArmorType.Signature:
                sb.Append(SignatureBegin);
                sb.Append(AddHeader(customComment)).Append(Helper.Eol);
                sb.Append(Base64Encode(data)).Append(Helper.Eol);
                if (Config.ChecksumRequired) sb.Append(Crc24Checksum(data)).Append(Helper.Eol);
                sb.Append(SignatureEnd);
                break;
        }

        return sb.ToString();
    }

    private static ArmorType ParseArmorType(string text)
    {
        var match = Regex.Match(text, BeginPattern);
        if (!match.Success) throw new ArgumentException("Unknown ASCII armor type.");

        return match.Value switch
        {
            { } value when value.Contains("SIGNED MESSAGE") => ArmorType.SignedMessage,
            { } value when value.Contains("PUBLIC KEY BLOCK") => ArmorType.PublicKey,
            { } value when value.Contains("PRIVATE KEY BLOCK") => ArmorType.PrivateKey,
            { } value when value.Contains("SIGNATURE") => ArmorType.Signature,
            _ => ArmorType.Message
        };
    }

    private static string AddHeader(string customComment = "")
    {
        var sb = new StringBuilder();
        if (Config.ShowVersion) sb.Append($"Version: {Config.Version}\n");

        if (Config.ShowComment) sb.Append($"Comment: {Config.Comment}\n");

        if (!string.IsNullOrEmpty(customComment)) sb.Append($"Comment: {customComment}\n");
        return sb.ToString();
    }

    private static string Base64Encode(byte[] data)
    {
        return Helper.ChunkSplit(Base64.ToBase64String(data));
    }

    private static string Crc24Checksum(byte[] bytes)
    {
        var crc = 0xb704ce;
        foreach (var data in bytes)
        {
            crc ^= data << 16;
            for (var i = 0; i < 8; i++)
            {
                crc <<= 1;
                if ((crc & 0x1000000) != 0) crc ^= 0x1864cfb;
            }
        }

        return Base64.ToBase64String(
            Helper.Pack32(crc & 0xffffff).Skip(1).ToArray()
        );
    }
}
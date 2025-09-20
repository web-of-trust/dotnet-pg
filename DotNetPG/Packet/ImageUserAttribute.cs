// Copyright (c) Dot Net Privacy Guard Project. All rights reserved.
// Licensed under the BSD 3-Clause License. See LICENSE in the project root for license information.

namespace DotNetPG.Packet;

/// <summary>
///     Image user attribute sub-packet class
/// </summary>
public class ImageUserAttribute(byte[] data) : UserAttributeSubPacket(Jpeg, data)
{
    public const int Jpeg = 1;

    public int HeaderLength => (Data[1] << 8) | Data[0];

    public int Version => Data[2];

    public int Encoding => Data[3];

    public byte[] ImageData => Data.Skip(HeaderLength).ToArray();

    /// <summary>
    ///     Read Image user attribute sub-packet from image data
    /// </summary>
    public static ImageUserAttribute FromImageData(
        byte[] imageData, int imageType = Jpeg
    )
    {
        return new ImageUserAttribute([
            0x10, 0x00, 0x01, (byte)imageType, ..new byte[12], ..imageData
        ]);
    }
}
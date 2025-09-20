using DotNetPG.Enum;
using DotNetPG.Type;

namespace DotNetPG.Key;

/// <summary>
/// OpenPGP sub key class.
/// </summary>
public class Subkey : ISubkey
{
    private readonly IKey _mainKey;

    private readonly ISubkeyPacket _keyPacket;

    private readonly IReadOnlyList<ISignaturePacket> _revocationSignatures;

    private readonly IReadOnlyList<ISignaturePacket> _bindingSignatures;

    public Subkey(
        IKey mainKey,
        ISubkeyPacket keyPacket,
        IList<ISignaturePacket> revocationSignatures,
        IList<ISignaturePacket> bindingSignatures
    )
    {
        _mainKey = mainKey;
        _keyPacket = keyPacket;
        _revocationSignatures = revocationSignatures.Where(signature => signature.IsSubkeyRevocation).ToList().AsReadOnly();
        _bindingSignatures = bindingSignatures.Where(signature => signature.IsSubkeyBinding).ToList().AsReadOnly();
    }
    
    public IKey  MainKey => _mainKey;

    public ISubkeyPacket KeyPacket => _keyPacket;

    public IReadOnlyList<ISignaturePacket> RevocationSignatures => _revocationSignatures;

    public IReadOnlyList<ISignaturePacket> BindingSignatures => _bindingSignatures;

    public int Version => _keyPacket.Version;

    public DateTime? ExpirationTime { get; }

    public DateTime? CreationTime => _keyPacket.CreationTime;

    public KeyAlgorithm KeyAlgorithm => _keyPacket.KeyAlgorithm;

    public byte[] Fingerprint => _keyPacket.Fingerprint;

    public byte[] KeyId => _keyPacket.KeyId;

    public int KeyLength => _keyPacket.KeyLength;

    public bool IsSigningKey => _keyPacket.IsSigningKey;

    public bool IsEncryptionKey => _keyPacket.IsEncryptionKey;

    public bool IsRevoked(IKey? verifyKey = null, ISignaturePacket? certificate = null, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public bool Verify(DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IUser RevokeBy(IPrivateKey signKey, string revocationReason = "",
        RevocationReasonTag revocationReasonTag = RevocationReasonTag.NoReason, DateTime? time = null)
    {
        throw new NotImplementedException();
    }

    public IPacketList PacketList { get; }

    public IList<IPacket> Packets { get; }
}

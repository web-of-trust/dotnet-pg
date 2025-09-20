using DotNetPG.Type;

namespace DotNetPG.Key;

/// <summary>
/// OpenPGP user class.
/// </summary>
public class User
{
    private readonly IKey _mainKey;

    private readonly IUserIdPacket _userIdPacket;
    
    private readonly IReadOnlyList<ISignaturePacket> _revocationSignatures;

    private readonly IReadOnlyList<ISignaturePacket> _selfCertifications;

    private readonly IReadOnlyList<ISignaturePacket> _otherCertifications;

    public User(
        IKey mainKey,
        IUserIdPacket userIdPacket,
        IList<ISignaturePacket> revocationSignatures,
        IList<ISignaturePacket> selfCertifications,
        IList<ISignaturePacket> otherCertifications
    )
    {
        _mainKey = mainKey;
        _userIdPacket = userIdPacket;
        _revocationSignatures = revocationSignatures.Where(signature => signature.IsCertRevocation).ToList().AsReadOnly();
        _selfCertifications = selfCertifications.Where(signature => signature.IsCertification).ToList().AsReadOnly();
        _otherCertifications = otherCertifications.Where(signature => signature.IsCertification).ToList().AsReadOnly();
    }

    public IKey MainKey => _mainKey;

    public IUserIdPacket UserId => _userIdPacket;

    public IReadOnlyList<ISignaturePacket> RevocationSignatures => _revocationSignatures;

    public IReadOnlyList<ISignaturePacket> SelfCertifications => _selfCertifications;

    public IReadOnlyList<ISignaturePacket> OtherCertifications => _otherCertifications;
}

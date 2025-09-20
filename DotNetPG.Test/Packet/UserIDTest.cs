using DotNetPG.Key;
using DotNetPG.Packet;
using Org.BouncyCastle.Security;

namespace DotNetPG.Test.Packet;

public class UserIDTest
{
    [Test]
    public void TestUserId()
    {
        const string name = "Nguyen Van Nguyen";
        const string email = "nguyennv1981@gmail.com";
        const string comment = "Viet Nam";

        var userId = new UserId($"{name} ({comment}) <{email}>");
        Assert.Multiple(() =>
        {
            Assert.That(userId.Name, Is.EqualTo(name));
            Assert.That(userId.Email, Is.EqualTo(email));
            Assert.That(userId.Comment, Is.EqualTo(comment));
        });

        var clone = UserId.FromBytes(userId.ToBytes());
        Assert.Multiple(() =>
        {
            Assert.That(clone.Name, Is.EqualTo(name));
            Assert.That(clone.Email, Is.EqualTo(email));
            Assert.That(clone.Comment, Is.EqualTo(comment));
        });
    }

    [Test]
    public void TestUserAttribute()
    {
        var imageData = SecureRandom.GetNextBytes(new SecureRandom(), 1000);
        var attrData = SecureRandom.GetNextBytes(new SecureRandom(), 1000);
        var imageAttr = ImageUserAttribute.FromImageData(imageData);
        var userAttr = new UserAttributeSubPacket(2, attrData);

        var packet = new UserAttribute([imageAttr, userAttr]);
        Assert.Multiple(() =>
        {
            Assert.That(packet.Attributes[0], Is.SameAs(imageAttr));
            Assert.That(packet.Attributes[1], Is.SameAs(userAttr));
        });

        var clone = UserAttribute.FromBytes(packet.ToBytes());
        Assert.Multiple(() =>
        {
            Assert.That(packet.Attributes[0], Is.SameAs(imageAttr));
            Assert.That(packet.Attributes[1], Is.SameAs(userAttr));
        });
    }
}

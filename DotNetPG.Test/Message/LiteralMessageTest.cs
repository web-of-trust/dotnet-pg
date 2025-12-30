using System.Text;
using Org.BouncyCastle.Utilities.Encoders;

namespace DotNetPG.Test.Message;

[TestFixture]
public class LiteralMessageTest
{
    private const string LiteralText = "Hello, world!";

    private const string Passphrase = "password";

    private const string RsaPrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=BhVr
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccNistP384PrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lNIEaUo/vxMFK4EEACIDAwShWpTI36as5whaeQhAb7nmDAloYAcpSnieMByS/JbS
DqbHQqK0y746KOxSOxBNjM4W6yEMhiyagZrmCWYKWk5uIz87A9JCph5zIsyEip67
tSnQBg2WnU8IKD1pI4SM537+BwMCaGiqteO7t63/kuJPTI90t4+r9nnTu2ihnZoX
rD4ZyZqndtia1SwpK8nfWelj/PCB4xn7VAZbCEI8FObNio2WNBnblcJL2B2Oju3e
xKB3oYAkmngmq2yYBvwXBz3dmWG0Kk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5u
djE5ODFAZ21haWwuY29tPoizBBMTCQA7FiEEMB8L/jaO93Bhq25n96WvN2jymmoF
AmlKP78CGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ96WvN2jymmrd
MAF/fg+Qqi7SuMOj2PIORP3z6nvg68p4JTXocSyyusiMLoiJ1LibHbdtHkD3S3zf
yC19AYDIHIB6U1aZoAz7viG8C3HtnaX1wa04p9OzOgttC4NsVJFrVUKKlXghE74P
Hwql6ZOc1gRpSj+/EgUrgQQAIgMDBHUeK591AXXGJjYSurDyw4Gr2VcS2UD2MBAT
ewbVkZ14O01PW0c6dwmWD2fdRyiCCCN0I4+g9fn53yf/Sar7zQUjDP8wigpdXSqf
+zWBdiCEMsDoqe98xOaAmm5rJLVjggMBCQn+BwMCTU/sQl1syWP/aMnTHl0xAvDK
fj8cQwleIk4jqzNAzssBt4t/ZRoU+uSXmJ8QaZOUb2ZVt0FIilWR8HIt+9EmOAmK
Rx2mmw3WzyQ/Pxb5Z6uIO1hz7UEk0pGeE6qylHuImAQYEwkAIBYhBDAfC/42jvdw
YatuZ/elrzdo8ppqBQJpSj+/AhsMAAoJEPelrzdo8ppqVbMBfiUMM3VtXmfIM8uc
k3AbYKUS0EJqSsFxi/E88CZFRobKVAtuDTC/FkZAapWvjxyp1wGAsorLxX4syMHl
t7KN4XKuQksjXrXHIeShVuBrk8Ew4lwp29uB7sZwMzQk+jhlOyge
=WqW7
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccBrainpoolPrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lKYEaUpAEhMJKyQDAwIIAQEHAgMEPlJmtGx5mICYEgRGRRucDd7eLdG4FrwENQMX
+igXpWYxb18u8DYsQK2egCGILBW1zYt6pWHeQsQgC71CrO4ZlP4HAwJkuknkdbJ0
0/+zyIJY2R2jle684DEY8AY6WzJZlD76YTqoG5wphk+vvExY5cbALPWnJOO1FZUH
l/QiH+1cSCB/lV72NvwANRdYzDPA1yT9tCpOZ3V5ZW4gVmFuIE5ndXllbiA8bmd1
eWVubnYxOTgxQGdtYWlsLmNvbT6IkwQTEwgAOxYhBCP7/IKGPFi3f8F/0G6mMM70
xXvoBQJpSkASAhsDBQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEG6mMM70
xXvoHywA/ij264z8bgVKfEQOZaQEf9AnSVYTQAg5zPRdOe8oug3rAQCkB4UcFMxi
Wu/PDK0pBfRzKG//sImcXD06epAgvD89A5yqBGlKQBISCSskAwMCCAEBBwIDBCyM
kXIHirMuOvLQDi655EU5EfA0PYgzw1VitebYzlJLE9eWg7M0Pod15NJuoQL7du44
/npX2xpPaEhbO32yRakDAQgH/gcDAnTDuDLpNF1U/0ad/xSOcP2ZLiwOIszsyCHe
x39qu8f3EN8ZWiC6ozLkS5I0O8gPZrJYlZqLqa3ZEls6l2/auHPVg9Uvzj0ZmEwa
dssUuE6IeAQYEwgAIBYhBCP7/IKGPFi3f8F/0G6mMM70xXvoBQJpSkASAhsMAAoJ
EG6mMM70xXvo0Y8BAIt3srVH8jDpoUs4fvjAlo4EAebKZ6wP8WHJ4lIilulEAP9f
M2eW+sS8HCEkqpccy8Imc0abq4+voVjMiis6bc4CCQ==
=FrF9
-----END PGP PRIVATE KEY BLOCK-----";

    private const string EccCurve25519PrivateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEaUpAYRYJKwYBBAHaRw8BAQdAxNFrk1BAfIODwbzj7j+cQn+35C0ID1hj60Cy
U86oPb7+BwMC1CeSZdUORST/aVd530V+DW5zuycHwH/RwoJ7Fs1lsbK0irLBs3sH
sfXQkd/c9hW76EfkZiR2JIiJK46u1jX/SFI0ae8l/5130it2HO2rF7QqTmd1eWVu
IFZhbiBOZ3V5ZW4gPG5ndXllbm52MTk4MUBnbWFpbC5jb20+iJMEExYKADsWIQQ6
dYnwWZSnUDoorfViUvVkpTtJXgUCaUpAYQIbAwULCQgHAgIiAgYVCgkICwIEFgID
AQIeBwIXgAAKCRBiUvVkpTtJXuBLAQCPA/cVcjviwsa8fDCY8WW46xW8ZFeCn69i
N5gMYTiyRQD/W0zw1meGly9UndofQZY60vxm5klsPKCC6t+4iZqZ0wWJAbMEEAEK
AB0WIQTRCK9znXXCFbM9ac6tqwDmwVfMDQUCaUu2TgAKCRCtqwDmwVfMDZjNDACq
5vjMNMyYvBIA95PG88l1x2AV38f1B9uvAhmhIonWksrTXErCcO1ijQYJr1Q9hJQu
BeEZN15YJhzLoMuXwvCfyK6YIaTIQsbuYY/yA7yak1Ly/j/YYfa5ga+U0ENBQFPQ
hBC/DRtur3H1VYf54GuBMSGQffer6+9s7nclwnYPLIeefNnEf1S9yBX6er6++Xfq
27REaP4vLZfbs7+lo9YPGtDdH+H7zoy4ctmJx1raGw96tIOEcJYeEFwps0+n+ZAW
f5WkJeJcQlZ8urKvfjzc3aqpE3Q2wJmQ4ewYxc3wU2WZPDiurkDtoJqmvvVf2KRx
pumpe4K21x9AYeggduKrWHPIxYs4rxPUaqPT8iN6Jv15jW+Tps4xcF0kvxyfOWdR
CZ1bB/xMz2mC4f/PehpaNWAN/C2vw57sLVa7foi3YbUV2RRYwm5kG2ijkLmr8OmG
dXBttqkTrmFpVVqY9k1SfjVH45+1TXOVCDeEEA8lk0OH/LuqhB6A5EkvvrF2eYqc
iwRpSkBhEgorBgEEAZdVAQUBAQdAcwCnokWFZCcGwu+0MCh7vBjeHa5cgc1q413D
gKuPRE4DAQgH/gcDAl+Lah979ZBs/1p4eEQliiPQ21yeehBx2czJYfSLxVA96GW1
QHlbn0viwO6B0TVd5TkqqPFu91hZ21STZxzmIm70IqaOegvXzQr8HplfwpGIeAQY
FgoAIBYhBDp1ifBZlKdQOiit9WJS9WSlO0leBQJpSkBhAhsMAAoJEGJS9WSlO0le
03MA+gPUPzX0LqO+OuPmwiuYEJibUneKde3nU2NE5kGplgf2AP9rU8+rOkhvrj0t
Dt8BTpBpZ769B0GLXv0Pe6k4098TAg==
=AxjL
-----END PGP PRIVATE KEY BLOCK-----";

    private const string RsaPublicKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

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
2KIGKrtNbt8EeTUzL33XMxSKMMXE99X76A==
=4T8l
-----END PGP PUBLIC KEY BLOCK-----";

    private const string EccNistP384PublicKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mG8EaUo/vxMFK4EEACIDAwShWpTI36as5whaeQhAb7nmDAloYAcpSnieMByS/JbS
DqbHQqK0y746KOxSOxBNjM4W6yEMhiyagZrmCWYKWk5uIz87A9JCph5zIsyEip67
tSnQBg2WnU8IKD1pI4SM5360Kk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5udjE5
ODFAZ21haWwuY29tPoizBBMTCQA7FiEEMB8L/jaO93Bhq25n96WvN2jymmoFAmlK
P78CGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ96WvN2jymmrdMAF/
fg+Qqi7SuMOj2PIORP3z6nvg68p4JTXocSyyusiMLoiJ1LibHbdtHkD3S3zfyC19
AYDIHIB6U1aZoAz7viG8C3HtnaX1wa04p9OzOgttC4NsVJFrVUKKlXghE74PHwql
6ZO4cwRpSj+/EgUrgQQAIgMDBHUeK591AXXGJjYSurDyw4Gr2VcS2UD2MBATewbV
kZ14O01PW0c6dwmWD2fdRyiCCCN0I4+g9fn53yf/Sar7zQUjDP8wigpdXSqf+zWB
diCEMsDoqe98xOaAmm5rJLVjggMBCQmImAQYEwkAIBYhBDAfC/42jvdwYatuZ/el
rzdo8ppqBQJpSj+/AhsMAAoJEPelrzdo8ppqVbMBfiUMM3VtXmfIM8uck3AbYKUS
0EJqSsFxi/E88CZFRobKVAtuDTC/FkZAapWvjxyp1wGAsorLxX4syMHlt7KN4XKu
QksjXrXHIeShVuBrk8Ew4lwp29uB7sZwMzQk+jhlOyge
=L5p6
-----END PGP PUBLIC KEY BLOCK-----";

    private const string EccBrainpoolPublicKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mFMEaUpAEhMJKyQDAwIIAQEHAgMEPlJmtGx5mICYEgRGRRucDd7eLdG4FrwENQMX
+igXpWYxb18u8DYsQK2egCGILBW1zYt6pWHeQsQgC71CrO4ZlLQqTmd1eWVuIFZh
biBOZ3V5ZW4gPG5ndXllbm52MTk4MUBnbWFpbC5jb20+iJMEExMIADsWIQQj+/yC
hjxYt3/Bf9BupjDO9MV76AUCaUpAEgIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIe
BwIXgAAKCRBupjDO9MV76B8sAP4o9uuM/G4FSnxEDmWkBH/QJ0lWE0AIOcz0XTnv
KLoN6wEApAeFHBTMYlrvzwytKQX0cyhv/7CJnFw9OnqQILw/PQO4VwRpSkASEgkr
JAMDAggBAQcCAwQsjJFyB4qzLjry0A4uueRFORHwND2IM8NVYrXm2M5SSxPXloOz
ND6HdeTSbqEC+3buOP56V9saT2hIWzt9skWpAwEIB4h4BBgTCAAgFiEEI/v8goY8
WLd/wX/QbqYwzvTFe+gFAmlKQBICGwwACgkQbqYwzvTFe+jRjwEAi3eytUfyMOmh
Szh++MCWjgQB5spnrA/xYcniUiKW6UQA/18zZ5b6xLwcISSqlxzLwiZzRpurj6+h
WMyKKzptzgIJ
=2/C1
-----END PGP PUBLIC KEY BLOCK-----";

    private const string EccCurve25519PublicKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaUpAYRYJKwYBBAHaRw8BAQdAxNFrk1BAfIODwbzj7j+cQn+35C0ID1hj60Cy
U86oPb60Kk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5udjE5ODFAZ21haWwuY29t
PoiTBBMWCgA7FiEEOnWJ8FmUp1A6KK31YlL1ZKU7SV4FAmlKQGECGwMFCwkIBwIC
IgIGFQoJCAsCBBYCAwECHgcCF4AACgkQYlL1ZKU7SV7gSwEAjwP3FXI74sLGvHww
mPFluOsVvGRXgp+vYjeYDGE4skUA/1tM8NZnhpcvVJ3aH0GWOtL8ZuZJbDyggurf
uImamdMFiQGzBBABCgAdFiEE0Qivc511whWzPWnOrasA5sFXzA0FAmlLtk4ACgkQ
rasA5sFXzA2YzQwAqub4zDTMmLwSAPeTxvPJdcdgFd/H9QfbrwIZoSKJ1pLK01xK
wnDtYo0GCa9UPYSULgXhGTdeWCYcy6DLl8Lwn8iumCGkyELG7mGP8gO8mpNS8v4/
2GH2uYGvlNBDQUBT0IQQvw0bbq9x9VWH+eBrgTEhkH33q+vvbO53JcJ2DyyHnnzZ
xH9UvcgV+nq+vvl36tu0RGj+Ly2X27O/paPWDxrQ3R/h+86MuHLZicda2hsPerSD
hHCWHhBcKbNPp/mQFn+VpCXiXEJWfLqyr3483N2qqRN0NsCZkOHsGMXN8FNlmTw4
rq5A7aCapr71X9ikcabpqXuCttcfQGHoIHbiq1hzyMWLOK8T1Gqj0/Ijeib9eY1v
k6bOMXBdJL8cnzlnUQmdWwf8TM9pguH/z3oaWjVgDfwtr8Oe7C1Wu36It2G1FdkU
WMJuZBtoo5C5q/DphnVwbbapE65haVVamPZNUn41R+OftU1zlQg3hBAPJZNDh/y7
qoQegORJL76xdnmKuDgEaUpAYRIKKwYBBAGXVQEFAQEHQHMAp6JFhWQnBsLvtDAo
e7wY3h2uXIHNauNdw4Crj0ROAwEIB4h4BBgWCgAgFiEEOnWJ8FmUp1A6KK31YlL1
ZKU7SV4FAmlKQGECGwwACgkQYlL1ZKU7SV7TcwD6A9Q/NfQuo7464+bCK5gQmJtS
d4p17edTY0TmQamWB/YA/2tTz6s6SG+uPS0O3wFOkGlnvr0HQYte/Q97qTjT3xMC
=0tFF
-----END PGP PUBLIC KEY BLOCK-----";

    [Test]
    public void TestVerifyRsaSignedMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

xA0DAAgBrasA5sFXzA0ByxNiAGlTjJtIZWxsbywgd29ybGQhwsEhBAABCABVBQJpU4ybFiEE0Qiv
c511whWzPWnOrasA5sFXzA0JEK2rAObBV8wNLRQAAAAAABQAEHNhbHRAcGhwLW9wZW5wZ3Aub3Jn
GA/QGm4W3dfhyuMekpQQLQAAYicMAJCiM7mPetqlmvUYBr8LascLywyx1Pc1szyYK0kcWGxnsjRZ
JV/pW+pwWdQhlr8l7DHScXIIrN1X5m2lRuccdb/Ax0IDVXiZDc6quQEzudWNyBcLzlczJTOudTro
S0ydRKH+HdyHJRLRliJzVu4TzInN0Uusml/Tqz8dM1RxhDqENGH2NihoKweChKW6sAA28yjtohgO
rI1V1xNm6gMRre3b6Ft5fcIIyfk9ygZQaeCPZY7YCrfywifr0pkvTHAESTDhjp3gOa9QQtNRtUkg
TQv1wJbOLHf0WQQjHa3yWwAgM+cKZAN3ZAZGfEp9np7rvBzYSSiZXRaqLZEEZJZXx2wD1I8RzpXo
wBKzWEMxBljzEMqQn5myCbm+X3uEUOblM5mnM7pKtvs15Yk4U6PBVUbar9FMImqlKjwmwRuvHjTu
hnvv+EEwE2N8VMDQhTiyWSthiIVnpTnVZQTq9GgZ2clqxj7kpH/kCXnkM4OLq3dtpAiPhaqytblH
2ar9kTr23Q==
-----END PGP MESSAGE-----";
        const string signatureData = @"-----BEGIN PGP SIGNATURE-----

wsEhBAABCABVBQJpU5YIFiEE0Qivc511whWzPWnOrasA5sFXzA0JEK2rAObBV8wNLRQAAAAAABQA
EHNhbHRAcGhwLW9wZW5wZ3Aub3JnghxYdE+yWGC36DRdIZcMPAAAeOsMAK1HH+QJETR1ia1Gc8iF
9Ni9CyJHQGpH9j/vujfhE/WPkWjS3jvXHTjI+QX9xtaVZ4aJi5/07YpLwMmYjwd6ABKIxI7WfwOR
TJvue1HRL8Cd0Mw8tJ1bEjmS2unoZP3PoLgjezKRo+ED0GFOF9BPiUHNEe1BBCf+9qc2Kejfw4D7
q2M4bvanq2UuUfonUK0uFsaKlSaCKBcB9Mfk11RIgjyZiNQvUl9Ay/fTQE32A49bnSChVuIJZ49S
ZOXTmWry0kPbDH0RmQIbYc9P1nlXrcH22kovfpO7bkwegO9kPGVQysJ7LOnJ5F1qzIL4/UjSWsU5
Ygq8ajlzY4jsNIm5TkFRXVBdVXwNdAvN+BzglNNxC8qY47qrbuEuvsAO0UF01RZG/6tOT8SUxBXh
mT0qES8PGb1BD9i2WXUgM36VwK52prhSVA9yGXj29HUVIqUeSOpnnnHBhX+ZH5uCur8vBQvjEBKC
648DPWXWDFTUTZfrFiYRqNgecqvA382/Lfj52w==
-----END PGP SIGNATURE-----";
        
        var publicKey = OpenPGP.ReadPublicKey(RsaPublicKey);
        var message = OpenPGP.ReadLiteralMessage(messageData);
        var literalText = Encoding.UTF8.GetString(message.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));
        
        var verification = message.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("adab00e6c157cc0d")));
            Assert.That(verification.IsVerified, Is.True);
        });

        message = OpenPGP.CreateLiteralMessage(literalText);
        var signature = OpenPGP.ReadSignature(signatureData);
        verification = message.VerifyDetached([publicKey], signature)[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("adab00e6c157cc0d")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TestVerifyEccNistP384SignedMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

xA0DAAkT96WvN2jymmoByxNiAGlTjPRIZWxsbywgd29ybGQhwsALBAATCQBdBQJpU4z0FiEEMB8L
/jaO93Bhq25n96WvN2jymmoJEPelrzdo8ppqNRQAAAAAABQAGHNhbHRAcGhwLW9wZW5wZ3Aub3Jn
ipLAnQBXIRUfKooc3aFldpIAvLhinZZ/AADPfQGAz/wavQERqDrhtgGAOs4kmXCH3jSlZxN4mHem
YaCEI1x+420RqYM0ppcffEAeoM8nAYCZe4WznFq2z/JGjy1yNUgWQ8bQb86UJH0weVr7D0uVQfka
+SomGPBET5KuDafrR38=
-----END PGP MESSAGE-----";
        const string signatureData = @"-----BEGIN PGP SIGNATURE-----

wsALBAATCQBdBQJpU5ZqFiEEMB8L/jaO93Bhq25n96WvN2jymmoJEPelrzdo8ppqNRQAAAAAABQA
GHNhbHRAcGhwLW9wZW5wZ3Aub3JnCxjgYVw0rXrd6LBmUXu2Pn7rqsWQVOUJAAAUSwGAghywv/wW
16siswAusJ9qpb+qEvTKUu6q0IVjs17yQCuNPX8XZj8RzwyRPALKte9VAX4vQY/bYhtg6qUeMqck
pQwiXPRLYvLo+Ui3iLQYq3DObr1TT8dvS+WIc/H8s61IuXQ=
-----END PGP SIGNATURE-----";
        
        var publicKey = OpenPGP.ReadPublicKey(EccNistP384PublicKey);
        var message = OpenPGP.ReadLiteralMessage(messageData);
        var literalText = Encoding.UTF8.GetString(message.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));
        
        var verification = message.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("f7a5af3768f29a6a")));
            Assert.That(verification.IsVerified, Is.True);
        });
        
        message = OpenPGP.CreateLiteralMessage(literalText);
        var signature = OpenPGP.ReadSignature(signatureData);
        verification = message.VerifyDetached([publicKey], signature)[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("f7a5af3768f29a6a")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TestVerifyEccBrainpoolSignedMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

xA0DAAgTbqYwzvTFe+gByxNiAGlTjWVIZWxsbywgd29ybGQhwqMEABMIAFUFAmlTjWUWIQQj+/yC
hjxYt3/Bf9BupjDO9MV76AkQbqYwzvTFe+gtFAAAAAAAFAAQc2FsdEBwaHAtb3BlbnBncC5vcme3
SuUKEpOgQKtTLP9TqIu+AAARHQD/RuGEb5tnKutdI/hgBdjv8kvRjSq5YGIavOUVNxoKitEA/2wZ
bB/OAqpa8r+Tuu/40aS06jOgVwL2oDRp1q3PhGZ8
-----END PGP MESSAGE-----";
        const string signatureData = @"-----BEGIN PGP SIGNATURE-----

wqMEABMIAFUFAmlTlsIWIQQj+/yChjxYt3/Bf9BupjDO9MV76AkQbqYwzvTFe+gtFAAAAAAAFAAQ
c2FsdEBwaHAtb3BlbnBncC5vcmd+SQaQcrTpIiEc6dBs18voAACrCwD/ZPWq0Hs5gsjfDs0Ftt7N
NKYX5dUlXpufw7fC9ZcNyL0A/jzzaTeGnSADnjeFDsElwSjMrpTsgOHnj0RsaHthwrz0
-----END PGP SIGNATURE-----";

        var publicKey = OpenPGP.ReadPublicKey(EccBrainpoolPublicKey);
        var message = OpenPGP.ReadLiteralMessage(messageData);
        var literalText = Encoding.UTF8.GetString(message.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));
        
        var verification = message.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("6ea630cef4c57be8")));
            Assert.That(verification.IsVerified, Is.True);
        });

        message = OpenPGP.CreateLiteralMessage(literalText);
        var signature = OpenPGP.ReadSignature(signatureData);
        verification = message.VerifyDetached([publicKey], signature)[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("6ea630cef4c57be8")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TestVerifyEccCurve25519SignedMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

xA0DAAoWYlL1ZKU7SV4ByxNiAGlTl5ZIZWxsbywgd29ybGQhwrMEABYKAGUFAmlTl5YWIQQ6dYnw
WZSnUDoorfViUvVkpTtJXgkQYlL1ZKU7SV49FAAAAAAAFAAgc2FsdEBwaHAtb3BlbnBncC5vcmcw
MgYDBnnWa3kbrskwtTotv04i2uf6KCOCi6rfDKcYnwAAtr4BAKB4tiVDuH91ZywqhWL/rERrHO6l
e5HyUxXyjxT/tvmRAQAnfiKRdFkscnD4afw4Nu/FbN4TN62O5bm37EDkd7QvAA==
-----END PGP MESSAGE-----";
        const string signatureData = @"-----BEGIN PGP SIGNATURE-----

wrMEABYKAGUFAmlTlzYWIQQ6dYnwWZSnUDoorfViUvVkpTtJXgkQYlL1ZKU7SV49FAAAAAAAFAAg
c2FsdEBwaHAtb3BlbnBncC5vcmdVUySyoW9sinGEVibp/+JaqyKhCsUncxjGHzQ7ol1f3AAAIU0B
AOYcCNOGkctf0e3CcFbNHNz72QdPGTfFM9uchvi75jq7AQBBoMlEbET38/1euglzIJJrWHeZz/ve
nykaR8cvcCfMCg==
-----END PGP SIGNATURE-----";

        var publicKey = OpenPGP.ReadPublicKey(EccCurve25519PublicKey);
        var message = OpenPGP.ReadLiteralMessage(messageData);
        var literalText = Encoding.UTF8.GetString(message.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));
        
        var verification = message.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("6252f564a53b495e")));
            Assert.That(verification.IsVerified, Is.True);
        });

        message = OpenPGP.CreateLiteralMessage(literalText);
        var signature = OpenPGP.ReadSignature(signatureData);
        verification = message.VerifyDetached([publicKey], signature)[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("6252f564a53b495e")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TestVerifyEd25519SignedMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

xDYGAAgbELV5sdslMqOJ5z7EQmQkiyLLGGxPBgmml+TVLfpscisMHx4nwYpWcI9lJewnutmsyQHL
E2IAaVOPyEhlbGxvLCB3b3JsZCHCkgYAGwgAAAAzBQJpU4/IIiEGyxhsTwYJppfk1S36bHIrDB8e
J8GKVnCPZSXsJ7rZrMkJEMsYbE8GCaaXAAAAAOrKELV5sdslMqOJ5z7EQmQkiyKvUI0VhuqmN8u0
ygM/YUyWLg7SHN5p/J0J2BOe8QHymIBfKQtZLr2DRJzvA21yRiydtyvscQipOcFA6nmA8o4H
-----END PGP MESSAGE-----";
        const string signatureData = @"-----BEGIN PGP MESSAGE-----

xDYGAAgbELV5sdslMqOJ5z7EQmQkiyLLGGxPBgmml+TVLfpscisMHx4nwYpWcI9lJewnutmsyQHL
E2IAaVOPyEhlbGxvLCB3b3JsZCHCkgYAGwgAAAAzBQJpU4/IIiEGyxhsTwYJppfk1S36bHIrDB8e
J8GKVnCPZSXsJ7rZrMkJEMsYbE8GCaaXAAAAAOrKELV5sdslMqOJ5z7EQmQkiyKvUI0VhuqmN8u0
ygM/YUyWLg7SHN5p/J0J2BOe8QHymIBfKQtZLr2DRJzvA21yRiydtyvscQipOcFA6nmA8o4H
-----END PGP MESSAGE-----";
        const string keyData = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----";

        var publicKey = OpenPGP.ReadPublicKey(keyData);
        var message = OpenPGP.ReadLiteralMessage(messageData);
        var literalText = Encoding.UTF8.GetString(message.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));

        var verification = message.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("cb186c4f0609a697")));
            Assert.That(verification.IsVerified, Is.True);
        });

        message = OpenPGP.CreateLiteralMessage(literalText);
        var signature = OpenPGP.ReadSignature(signatureData);
        verification = message.VerifyDetached([publicKey], signature)[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("cb186c4f0609a697")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TestSignMessageWithRsaKey()
    {
        var privateKey = OpenPGP.DecryptPrivateKey(RsaPrivateKey, Passphrase);
        var literalMessage = OpenPGP.CreateLiteralMessage(LiteralText);
        var signedMessage = OpenPGP.Sign(literalMessage, [privateKey]);
        var signature = signedMessage.Signature;
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("adab00e6c157cc0d")));

        signature = OpenPGP.SignDetached(literalMessage, [privateKey]);
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("adab00e6c157cc0d")));
    }

    [Test]
    public void TestSignMessageWithEccNistKey()
    {
        var privateKey = OpenPGP.DecryptPrivateKey(EccNistP384PrivateKey, Passphrase);
        var literalMessage = OpenPGP.CreateLiteralMessage(LiteralText);
        var signedMessage = OpenPGP.Sign(literalMessage, [privateKey]);
        var signature = signedMessage.Signature;
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("f7a5af3768f29a6a")));

        signature = OpenPGP.SignDetached(literalMessage, [privateKey]);
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("f7a5af3768f29a6a")));
    }

    [Test]
    public void TestSignMessageWithEccBrainpoolKey()
    {
        var privateKey = OpenPGP.DecryptPrivateKey(EccBrainpoolPrivateKey, Passphrase);
        var literalMessage = OpenPGP.CreateLiteralMessage(LiteralText);
        var signedMessage = OpenPGP.Sign(literalMessage, [privateKey]);
        var signature = signedMessage.Signature;
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("6ea630cef4c57be8")));

        signature = OpenPGP.SignDetached(literalMessage, [privateKey]);
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("6ea630cef4c57be8")));
    }

    [Test]
    public void TestSignMessageWithEccCurve25519Key()
    {
        var privateKey = OpenPGP.DecryptPrivateKey(EccCurve25519PrivateKey, Passphrase);
        var literalMessage = OpenPGP.CreateLiteralMessage(LiteralText);
        var signedMessage = OpenPGP.Sign(literalMessage, [privateKey]);
        var signature = signedMessage.Signature;
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("6252f564a53b495e")));

        signature = OpenPGP.SignDetached(literalMessage, [privateKey]);
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("6252f564a53b495e")));
    }

    [Test]
    public void TestSignMessageWithEd25519Key()
    {
        const string keyData = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----";

        var privateKey = OpenPGP.ReadPrivateKey(keyData);
        var literalMessage = OpenPGP.CreateLiteralMessage(LiteralText);
        var signedMessage = OpenPGP.Sign(literalMessage, [privateKey]);
        var signature = signedMessage.Signature;
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("cb186c4f0609a697")));

        signature = OpenPGP.SignDetached(literalMessage, [privateKey]);
        Assert.That(signature.SigningKeyIDs[0], Is.EqualTo(Hex.Decode("cb186c4f0609a697")));
    }
}

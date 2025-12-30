namespace DotNetPG.Test.Message;

using System.Text;
using Enum;
using Org.BouncyCastle.Utilities.Encoders;

[TestFixture]
public class EncryptedMessageTest
{
    private const string Passphrase = "password";

    private const string LiteralText = "Hello, world!";

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

    [Test]
    public void TestDecryptEncryptedMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

wcDMA5yNZqaqJZXJAQv+IAdDPKgsS+QII8HKykibTb7QzW4s5LyVUTEwvM55mzq5pH3hf666eV2A
lMFwiO51UhNvcrR4wTVSWMFgt7/PjCTuZv256cRJo2ewkUcHsIjf4BYSYWjwng2SpdUWpAcQZCfJ
FlNbuGN4QN5sUDkEIUAEzrt2pQW9OJcdieGJdCKsbbDkKVpG5Wgm9rcgD9iRhsEd1pXbGHNrq2PJ
IlOUrg22UMu+X+lu8b+iHpicI3MYFcEzxAZDS88HfayB9Kx8btoD5tn2P5fqtZ/igwiNV7un42jM
c96/UUio1/BsbJO2Phpv0kBkoaZ3Yci/kDIVkPCY3GpLTE7hIGplrsf4dkz+q+aT2ibnLDfnB/4P
dNM8S6X7c3Gri9hUj4mPxZELiNU6QCyoDypMAWgJImsav9kvbxv2NxHU3XFA+vbyB5IDnDH+Pmj/
h14me8DoU8A9Jb76zOck2Dw5GkLbr4BHLRU5PyCMf6EQ0lcdRFiSc0DEr2sp+gBFPXfiLIAjzSbq
wZ4DFXtrYJfH6RcSAwMEkPdPnhNmfTWOhMaB3aXYqcYUo3x4zGYYaPJ1oAKdLikunftm6l1ILwUQ
4qKdPwhHcPDS67cZ2795pPjc3i07SwzQUFvXtrzpnfN0UO20qluYcrBGbNRkd2RhMIIzYKOpMEBw
0AD1ntudlN+N/kvtu684ltOifxehlMTIYltmn8BXmGnPSqN7JGJmlE1lzCyPjMF+A/Asxd89jm+/
EgIDBALew+OC0dmSZdZ3syVJB5fxc6ZbBDNXJQMciEaio5n2dP5dv7qW6IG1V2P0pIDvkPVqAEjO
KveK1UbSgz25lr4wIxEUZ2RZmnfnMalZYMv8RLQ3n3GvqNWg025l6rK53m/j/nAdM0MGX9HBjSqh
joW/wV4Dbc3/HwOhSoQSAQdAJD4wPK4PyrHY9FIJ0JEmI4jPUZJKnna8fFtAYGuiCw0wxPe+1f3E
9GCvlhYUJGVj8s8CpRkY9K+eu/5v+TM7YDpnCboSnhYGQJUEpzdJ1vl4wy4ECQMI6kMCBzlC7yjg
NPxPvr6Mw3Iu3oAvXcIxO4yNrXXvtpCcdCIVML10p3Ss0j4BhsNX+JZ8v2Q4ER/Jt1osYdYQ0sOI
J9qDlRWGWRQNy+77PTvFXtYe8ju6vWTbkN5b/vvK5y1HBVVsSYbsJQ==
-----END PGP MESSAGE-----";
        
        var encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        var decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [], [Passphrase]);
        var literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));

        var privateKey = OpenPGP.DecryptPrivateKey(RsaPrivateKey, Passphrase);
        decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [privateKey], []);
        literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));

        privateKey = OpenPGP.DecryptPrivateKey(EccNistP384PrivateKey, Passphrase);
        decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [privateKey], []);
        literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));

        privateKey = OpenPGP.DecryptPrivateKey(EccBrainpoolPrivateKey, Passphrase);
        decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [privateKey], []);
        literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));
        
        privateKey = OpenPGP.DecryptPrivateKey(EccCurve25519PrivateKey, Passphrase);
        decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [privateKey], []);
        literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestDecryptAepdMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

wy4ECQMI+VCqcbk6aELg9rKgJfYF5UVX2qBP7p16eZZlYuN/FGw1PexDoGCou/ND0j4B6d8cyKYl
xSlnTbJ7A/Op4bwSdSTh1y1SizOJorLX3vvrY6wuxftVALrUZklicsFrIOpm9YAbLGGEJCMPjQ==
-----END PGP MESSAGE-----";
        
        var encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        var decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [], [Passphrase]);
        var literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));
    }
    
    [Test]
    public void TestDecryptX25519AeadOcbMessage()
    {
        const string privatekeyData = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

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
        const string messageData = @"-----BEGIN PGP MESSAGE-----

wV0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmHzxjV8bU/gXzO
WgBM85PMiVi93AZfJfhK9QmxfdNnZBjeo1VDeVZheQHgaVf7yopqR6W1FT6NOrfS
aQIHAgZhZBZTW+CwcW1g4FKlbExAf56zaw76/prQoN+bAzxpohup69LA7JW/Vp0l
yZnuSj3hcFj0DfqLTGgr4/u717J+sPWbtQBfgMfG9AOIwwrUBqsFE9zW+f1zdlYo
bhF30A+IitsxxA==
-----END PGP MESSAGE-----";

        var privateKey = OpenPGP.ReadPrivateKey(privatekeyData);
        var encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        var decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [privateKey], []);
        var literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.That(literalText, Is.EqualTo(LiteralText));
    }

    [Test]
    public void TestDecryptAeadEaxMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

w0AGHgcBCwMIpa5XnR/F2Cv/aSJPkZmTs1Bvo7WaanPP+MXvxfQcV/tU4cImgV14
KPX5LEVOtl6+AKtZhsaObnxV0mkCBwEGn/kOOzIZZPOkKRPI3MZhkyUBUifvt+rq
pJ8EwuZ0F11KPSJu1q/LnKmsEiwUcOEcY9TAqyQcapOK1Iv5mlqZuQu6gyXeYQR1
QCWKt5Wala0FHdqW6xVDHf719eIlXKeCYVRuM5o=
-----END PGP MESSAGE-----";
        
        var encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        var decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [], [Passphrase]);
        var literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.Multiple(() =>
        {
            Assert.That(encryptedMessage.SessionKey?.EncryptionKey, Is.EqualTo(Hex.Decode("3881bafe985412459b86c36f98cb9a5e")));
            Assert.That(encryptedMessage.SessionKey?.Aead, Is.EqualTo(AeadAlgorithm.Eax));
            Assert.That(literalText, Is.EqualTo(LiteralText));
        });
    }

    [Test]
    public void TestDecryptAeadOcbMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

wz8GHQcCCwMIVqKY0vXjZFP/z8xcEWZO2520JZDX3EawckG2EsOBLP/76gDyNHsl
ZBEj+IeuYNT9YU4IN9gZ02zSaQIHAgYgpmH3MfyaMDK1YjMmAn46XY21dI6+/wsM
WRDQns3WQf+f04VidYA1vEl1TOG/P/+n2tCjuBBPUTPPQqQQCoPu9MobSAGohGv0
K82nyM6dZeIS8wHLzZj9yt5pSod61CRzI/boVw==
-----END PGP MESSAGE-----";
        
        var encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        var decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [], [Passphrase]);
        var literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.Multiple(() =>
        {
            Assert.That(encryptedMessage.SessionKey?.EncryptionKey, Is.EqualTo(Hex.Decode("28e79ab82397d3c63de24ac217d7b791")));
            Assert.That(encryptedMessage.SessionKey?.Aead, Is.EqualTo(AeadAlgorithm.Ocb));
            Assert.That(literalText, Is.EqualTo(LiteralText));
        });
    }

    [Test]
    public void TestDecryptAeadGcmMessage()
    {
        const string messageData = @"-----BEGIN PGP MESSAGE-----

wzwGGgcDCwMI6dOXhbIHAAj/tC58SD70iERXyzcmubPbn/d25fTZpAlS4kRymIUa
v/91Jt8t1VRBdXmneZ/SaQIHAwb8uUSQvLmLvcnRBsYJAmaUD3LontwhtVlrFXax
Ae0Pn/xvxtZbv9JNzQeQlm5tHoWjAFN4TLHYtqBpnvEhVaeyrWJYUxtXZR/Xd3kS
+pXjXZtAIW9ppMJI2yj/QzHxYykHOZ5v+Q==
-----END PGP MESSAGE-----";

        var encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        var decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [], [Passphrase]);
        var literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.Multiple(() =>
        {
            Assert.That(encryptedMessage.SessionKey?.EncryptionKey, Is.EqualTo(Hex.Decode("1936fc8568980274bb900d8319360c77")));
            Assert.That(encryptedMessage.SessionKey?.Aead, Is.EqualTo(AeadAlgorithm.Gcm));
            Assert.That(literalText, Is.EqualTo(LiteralText));
        });
    }

    [Test]
    public void TestDecryptMessageUsingArgon2()
    {
        var messageData = @"-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 128-bit key
Comment: Session key: 01FE16BBACFD1E7B78EF3B865187374F

wycEBwScUvg8J/leUNU1RA7N/zE2AQQVnlL8rSLPP5VlQsunlO+ECxHSPgGYGKY+
YJz4u6F+DDlDBOr5NRQXt/KJIf4m4mOlKyC/uqLbpnLJZMnTq3o79GxBTdIdOzhH
XfA3pqV4mTzF
-----END PGP MESSAGE-----";
        
        var encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        var decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [], [Passphrase]);
        var literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.Multiple(() =>
        {
            Assert.That(encryptedMessage.SessionKey?.EncryptionKey, Is.EqualTo(Hex.Decode("01fe16bbacfd1e7b78ef3b865187374f")));
            Assert.That(literalText, Is.EqualTo(LiteralText));
        });
        
        messageData = @"-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 192-bit key
Comment: Session key: 27006DAE68E509022CE45A14E569E91001C2955...
Comment: Session key: ...AF8DFE194

wy8ECAThTKxHFTRZGKli3KNH4UP4AQQVhzLJ2va3FG8/pmpIPd/H/mdoVS5VBLLw
F9I+AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRys
LVg77Mwwfgl2n/d572WciAM=
-----END PGP MESSAGE-----";
        
        encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [], [Passphrase]);
        literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.Multiple(() =>
        {
            Assert.That(encryptedMessage.SessionKey?.EncryptionKey, Is.EqualTo(Hex.Decode("27006dae68e509022ce45a14e569e91001c2955af8dfe194")));
            Assert.That(literalText, Is.EqualTo(LiteralText));
        });
        
        messageData = @"-----BEGIN PGP MESSAGE-----
Comment: Encrypted using AES with 256-bit key
Comment: Session key: BBEDA55B9AAE63DAC45D4F49D89DACF4AF37FEF...
Comment: Session key: ...C13BAB2F1F8E18FB74580D8B0

wzcECQS4eJUgIG/3mcaILEJFpmJ8AQQVnZ9l7KtagdClm9UaQ/Z6M/5roklSGpGu
623YmaXezGj80j4B+Ku1sgTdJo87X1Wrup7l0wJypZls21Uwd67m9koF60eefH/K
95D1usliXOEm8ayQJQmZrjf6K6v9PWwqMQ==
-----END PGP MESSAGE-----";
        
        encryptedMessage = OpenPGP.ReadEncryptedMessage(messageData);
        decryptedMessage = OpenPGP.Decrypt(encryptedMessage, [], [Passphrase]);
        literalText = Encoding.UTF8.GetString(decryptedMessage.LiteralData.Data);
        Assert.Multiple(() =>
        {
            Assert.That(encryptedMessage.SessionKey?.EncryptionKey, Is.EqualTo(Hex.Decode("bbeda55b9aae63dac45d4f49d89dacf4af37fefc13bab2f1f8e18fb74580d8b0")));
            Assert.That(literalText, Is.EqualTo(LiteralText));
        });
    }
}

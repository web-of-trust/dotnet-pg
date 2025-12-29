using Org.BouncyCastle.Utilities.Encoders;

namespace DotNetPG.Test.Message;

[TestFixture]
public class SignedMessageTest
{
    private const string RsaPublicKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGlKP0MBDADA8nF1IvkpAaUY7+AKQoVOGs4rDMUhZYiVTmuYeR8RlhcYxqpF
jpPXEPb+jXM38qwRazYzblSCmshJmWqm4w3hlHW0jOW9gAzbNhB+c73aNVPBUYTg
IILtNiF7AivkYlBcdmzybvck/eBzvUDgvkeTNs99ztOMJ5Jli6ztCO84QS59tWpn
e4H1jdnkAF9j7kz3C0hVQv0AjVE/nkkNjPZiUPA6qhIrHjw3RDnZPx0KS2WbDJKn
fGDPj9drkufmUs+p28gvkge3MVnNweZSYv9utrbqB4Ez0B0e5jlw292vDwDLWnwg
u7uvtN8O7e24tbMufcHxZPfZVVZjq3mYbWAQoV8fWHe/cdRpkZ/J56yWis7i6iZ2
GiW9IxgPCNb6lbF+5BnQDm0j4/TLHYwYxOOl3TpKpxtgOcZ5pGTqKb9dHtorrVcA
iB8BRDcyIuPL5upti70R8fgtY4+4wHgHk4KDvv8QTawPSySmL/Yxc7vATFx7W4eD
3OOo3dUYVTOLQssAEQEAAbQqTmd1eWVuIFZhbiBOZ3V5ZW4gPG5ndXllbm52MTk4
MUBnbWFpbC5jb20+iQHRBBMBCgA7FiEE0Qivc511whWzPWnOrasA5sFXzA0FAmlK
P0MCGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQrasA5sFXzA2ihQv+
IPk4aDuXNMSG5JTslmQ3QPjoLkP7fRpDsNryFTOnR0Pp/HXMs26dceCSOBNAF7eL
MoJW75mNb+VYymtJRzrKcLkh0gDcbuSllfp7eDw0Xe0cFaOdUMgejGZmRinw51TE
UM3d1y3HgbA/nS+91aRjZF0ooYSaTVO8dIwaacOJY0IJK6qu4uPfnXzzjQsN6yTi
TcS24ePSzmDQtQ8f6Nk3ngeRkrwjjl2w8y0AcO+UX+2Mu0qwT3vy7Tn1YGjEZISL
0kLILkbpo5mztLUKWQue5gVYke+kq/nf1+xEkPWM3ynLl9D49yiOj3Da9jnnETzb
b9Z/eQbHDICgOAXZfk85+ITRwunKeO9RGIxtlx6aXIewlzAfPg53t+m5dw95IpY3
jNS8fhvS/xmgnqwaOUBMlugYhdNnZ7zMKjflXkD+btjwPDsS4l1fnb2swMC9mWhL
oKaznoR4i3P3VYk9222vbraeTX8SpU24m4xVpfg66eboLlTZBEwNQ8TYLwEfNhPj
uQGNBGlKP0MBDADA08GSiH87kcWiZEjyCRqyk6UHYcYqdnxE55SA7l3lOC/2VNiq
SP2tsH8kaOZcjjvK1MRYpxDBxYr0P00HNdRElZjiwTbU39MP1WBEnO6PzQNrV2NU
EyD3RgA3okHIMK+lGqn19sH05QT1JHnhC9LnUObpxABG/KxP6WmAjsZ9oYH7NMMI
L+LnbQFUJyT4jUHvlm5zqZYIgFWZcYBdnrPXEGFl6nN3VeXZhDUph5KTL9f8nhE3
VXBfuyffp+UURuP5ufQr14OA3RWYFiueS04r7dAuIadeCWYFDT+BngrK+nRhyic8
JfMGJ2TTywKMllAwFbdih6n82Ob3o8H7Jc6dz1jesMX0lz87sNPfT4wPXN9ekmba
PjbaPu6qQw9V+YCgrwVf6reDj1RPRHOtKtTsfwUcAX/EH/y0ydIPPeDwxS4SSGgY
DfTyINb2UjutbjGm3ubf2erCt1AiKTHjXi4O07fGyjF4CafA6EHgQxS7xAW8TG8Y
M48rHNGEBxJ++dsAEQEAAYkBtgQYAQoAIBYhBNEIr3OddcIVsz1pzq2rAObBV8wN
BQJpSj9DAhsMAAoJEK2rAObBV8wNrwUL/RP9HyT/eTLwT1eC+1mT5iZhcBY0s4bD
hcflsGz9nDT9W3Iqh/NSeiJIPb/yd2iSzlE6MCw5n0u0pAQC9ge5pMNr8OJu4pos
5FXUcOs4oNQLCTx14xEY73ZF0srxqfOa0YhXmgHPmkoiu4XDlC8TB4ATwrlvS0rn
X8PFqrDVjokl6LCwDBzK8NOtk+KPmQm4Vu6WjPmZ2LGG54COlX13wAxj2nucFKCx
kJetP78iYIEGqS7P27ZTGl/WL/KziqKLLo6n4quj4JwO1NgVY5mrLWRLQJeueQsR
QOjQ3w3mymvCG+cesNgZkth0d5YQoMjV9Lc+JrKv5d683tsNOr+3/fenJBmVc/S4
nveACPoU1AB0GxSyoc0TUjayfGPUdAjWFWatubsQ/HbK5q+lVRn+35D7xvu9nThL
QXb8d0gX4HwyvojHUg9UcJ8FKwi7xWlK8Qk3m5DL3Yh+RQlTBHcbjuim5Qi8w7wr
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

    private const string Ed25519PublicKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----

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

    [Test]
    public void TestVerifyRsaCleartextSignedMessage()
    {
        const string messageData = @"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello DotNetPG
What we need from the grocery store:

- -tofu
- -vegetables
- -noodles
-----BEGIN PGP SIGNATURE-----
Version: PHP Privacy v2

wsEhBAEBCABVBQJpUkqbFiEE0Qivc511whWzPWnOrasA5sFXzA0JEK2rAObBV8wNLRQAAAAAABQA
EHNhbHRAcGhwLW9wZW5wZ3Aub3JnTCKD2Jcs8TwwJtviWBIiUQAAh4sMAKYPE66OAE3Th076rT2R
vlIGb0Nqz9qaMeYb8E+YO22uc/lHrHwKnfrCY8iebGVm9JFpcx+rw/qRf0J/VHBEe7w0HwG7Nu6w
0cK9pCYXLgPlNV0HVJcaY2ajYe4jOdoQ3J14zwYNO+4HHBIpU5hXXq1i5IwFoXfPpJP7LJitQW9F
Uao3CQumb5sbzs9SIVDcVDXeomzLUckbLS3QFT2LC0HwVzdKLWfpcAPAZ33YxVLa+jEi4Dho96Ha
xglIcncFE28UesXDHVL73J14mY+sXABbHUh1jkhtzitAwoECOeH+yzSA2eWoHCvZCv1yyDb7ngrE
mG3FBrHqONAYKSktMcGOr827txve9gSHjyYuHixYzePIHhcej/K5R6pw8NELfqjFS8KhXOR/kp8x
a84kxcv9VDijmVP6/v9Jzo/QbjIr9IVHDmgXd8t+6/0heluLdcVxhnAPGIKMTh5UwLM8eTrc06FP
zKGyOhGHFaj/Mt0GYAJ4dVCgf5KAX7o4qnXvNA==
-----END PGP SIGNATURE-----";
        var publicKey = OpenPGP.ReadPublicKey(RsaPublicKey);
        var signedMessage = OpenPGP.ReadSignedMessage(messageData);
        var verification = signedMessage.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("adab00e6c157cc0d")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TestVerifyEccNistP384CleartextSignedMessage()
    {
        const string messageData = @"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA384

Hello DotNetPG
What we need from the grocery store:

- -tofu
- -vegetables
- -noodles
-----BEGIN PGP SIGNATURE-----

wsALBAETCQBdBQJpUmOEFiEEMB8L/jaO93Bhq25n96WvN2jymmoJEPelrzdo8ppqNRQAAAAAABQA
GHNhbHRAcGhwLW9wZW5wZ3Aub3JnJanUv7LByK39vkyrjmZJj/HW3xW0t/hZAACKOAGAhOlsrKuu
R26jtPq/lrlRjHKgOJgWms9RX4Sd1A3AijsFuDeJpcNsTJViN9HNOC5WAYCi+eAOWxR0yu4Hz39D
Yg0NWpFitC6CurLn0yLJD0M9Wmr05TijcUTa3XiULgyCF6M=
-----END PGP SIGNATURE-----
";
        var publicKey = OpenPGP.ReadPublicKey(EccNistP384PublicKey);
        var signedMessage = OpenPGP.ReadSignedMessage(messageData);
        var verification = signedMessage.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("f7a5af3768f29a6a")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TestVerifyEccBrainpoolCleartextSignedMessage()
    {
        const string messageData = @"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello DotNetPG
What we need from the grocery store:

- -tofu
- -vegetables
- -noodles
-----BEGIN PGP SIGNATURE-----

wqMEARMIAFUFAmlSY/EWIQQj+/yChjxYt3/Bf9BupjDO9MV76AkQbqYwzvTFe+gtFAAAAAAAFAAQ
c2FsdEBwaHAtb3BlbnBncC5vcmenu8cyvA8ZL35B8Ig2LZfVAADs6wD/Q2qPzyELUniNhO5VUCQ4
2BZoJ7Bk0HvDPauqjeG/9kcA/iz6VDLAdEG0TpUSTofKp1wCZ577qf0QhLGQPuwU5WUR
-----END PGP SIGNATURE-----";
        var publicKey = OpenPGP.ReadPublicKey(EccBrainpoolPublicKey);
        var signedMessage = OpenPGP.ReadSignedMessage(messageData);
        var verification = signedMessage.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("6ea630cef4c57be8")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TestVerifyEccCurve25519CleartextSignedMessage()
    {
        const string messageData = @"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Hello DotNetPG
What we need from the grocery store:

- -tofu
- -vegetables
- -noodles
-----BEGIN PGP SIGNATURE-----

wrMEARYKAGUFAmlSZCwWIQQ6dYnwWZSnUDoorfViUvVkpTtJXgkQYlL1ZKU7SV49FAAAAAAAFAAg
c2FsdEBwaHAtb3BlbnBncC5vcmcheQAuTTZ6z+HS5cr3uXrSkLyf3nm9wruVXeHGD155FQAA84IB
AKiLcpkB4P+yYwvxvNhgYJ9EVpCSE54N+PF+uiVGaoZIAQAHUmuQ3P9GTbAEEcyPB7M39qnABElt
tzcICs248gwDAg==
-----END PGP SIGNATURE-----";
        var publicKey = OpenPGP.ReadPublicKey(EccCurve25519PublicKey);
        var signedMessage = OpenPGP.ReadSignedMessage(messageData);
        var verification = signedMessage.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("6252f564a53b495e")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }

    [Test]
    public void TesterifyEd25519CleartextSignedMessage()
    {
        const string messageData = @"-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hello DotNetPG
What we need from the grocery store:

- -tofu
- -vegetables
- -noodles
-----BEGIN PGP SIGNATURE-----
Version: PHP Privacy v2

wpIGARsIAAAAMwUCaVJkeyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJCRDLGGxP
BgmmlwAAAACSCRDFk86YrONB720Q1D1exI7poLQs0eLvODtxKHLM0oWob7VZkYLjZQWsjLf90qO/
Ka9+G5mkTqi0apUHHbpwQ02N6UoYKhAw+GjbJIF1czAaCA==
-----END PGP SIGNATURE-----";
        var publicKey = OpenPGP.ReadPublicKey(Ed25519PublicKey);
        var signedMessage = OpenPGP.ReadSignedMessage(messageData);
        var verification = signedMessage.Verify([publicKey])[0];
        Assert.Multiple(() =>
        {
            Assert.That(verification.KeyId, Is.EqualTo(Hex.Decode("cb186c4f0609a697")));
            Assert.That(verification.IsVerified, Is.True);
        });
    }
}

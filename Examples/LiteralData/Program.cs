using DotNetPG;
using DotNetPG.Common;
using DotNetPG.Enum;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

const string passphrase = "oTK5>A}dP=.gW,^5.PzpL@*8Nz?7lj0:";

const string rsaKeyData = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

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
37FNtCKBugJiF7j3Jn+TMj4dJOs=
-----END PGP PRIVATE KEY BLOCK-----";

const string eccKeyData = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

xcBIBGlfVq0TBSuBBAAjBCMEACv0ryiZJRYmbRVNCpiGq/ft0ecue65T2nma6LhDgknF+f4UYj6o
tCy14VcpytRTOsJqx1AFZuOeeeqm8RyI1PJWAfmqbeJGP7TnoJxvesMnTwnEbciU9/1icHAN+sAc
8vWQgMFnXTP9/YO8dWxFsBAw294KUglRamXcOTE+0gVn95Fn/gkDCP7XyPg3rM194JNBiaBnl71a
uiVufGL+lZCeZELmWc1GU0wjg3hHfy7AA2WT1mIOf/P/tloLfLLcPRcZKP2y44z372BfnikjnHBw
AJBUqUZXbB9Xk3KzCENkL8N/546Rfz4qnisgUDYyBkZI6NZ6HFN/zSpOZ3V5ZW4gVmFuIE5ndXll
biA8bmd1eWVubnYxOTgxQGdtYWlsLmNvbT7CwFMEEBMKAIMFAmlfVq0WIQTk3mSBRFgxfP2ndUW+
cTH0MioK7wkQvnEx9DIqCu8CGwMDCwkHBCICAwEFFQgMCg4FFgABAgMCHgsCGQE9FAAAAAAAFAAg
c2FsdEBwaHAtb3BlbnBncC5vcmcmhxEIyerQ658WBLj+ZYMfb7gWUXmMxFyzG055ESdLbwAACEkC
CJ2/Lrwyu7iRT2GEyCrDzukxNVFPYJ9EaKGO6zUSNE9cmfAEzhIHUwvxBht3Ov+xuFjhHW0tmNIG
DQTXT95/Zha2AgiBcu+XpDZWzzSG6M+LZISuS9kGYaO7fZIH+Qp4noePIJYJoJTzAENcg2573PKv
DDKj/gd1iie9pDu/5SETLqqqks0sTmd1eWVuIFZhbiBOZ3V5ZW4gPG5ndXllbm52QGl3YXl2aWV0
bmFtLmNvbT7CwFEEEBMKAIAFAmlfVq0WIQTk3mSBRFgxfP2ndUW+cTH0MioK7wkQvnEx9DIqCu8C
GwMDCwkHBCICAwEFFQgMCg4FFgABAgMCHgs9FAAAAAAAFAAgc2FsdEBwaHAtb3BlbnBncC5vcmcp
ZE7f/JkyiZvKr6AqBC+iCq5IHmF6OlTcuLCv+XJmaAAAzMcCCQEgSyOEFgNjyDDe5IMlkoMmejod
+C0s49E6Ange3dFfDes53Q9SiiXEmrwL4UEFKcs2oAsCbEUBIX+hrvrp97/kAAIIvWAmwXKrONAh
Bif9HtTL1kKSG3yFxTPhSyePqx7SYJK7SEWgtbb4Zdu5tGwQsx3TbGGTZoftxdfmKA9IWJ9xwELH
wEsEaV9WrRIFK4EEACMEIwQBQZmBxfgjUWCabgrSUPd0pZZ+EtJP5f9fMOt0bUdFS7mofy/osnKT
V731aWqCWDBvXH0XXeXzPryzDP90iY4KJAAAOligNQ/GdzWIPJ+9lVPiUU/yd9idgX9tQh8nBs7h
hM1PYSZTkBg+0FnTkqU+hIh4GLuP36JRgWyUIPZvf84Xc+IDAAoJ/gkDCAxjZCzxUjCl4FKolAma
RfybEtUkBJ8csUMScZz0CKtE/gGWHYyUlRd+nWuGcL/siaditIsPbV6QBA/BR5cIYsEbu4MaO2eM
Pe+VB3ohji0XMAMaw1V2XOt0o7dLPeWhgbBk1q80wsCU7veUcFYymWfCwDkEGBMKAGgFAmlfVq0W
IQTk3mSBRFgxfP2ndUW+cTH0MioK7wkQvnEx9DIqCu8CGww9FAAAAAAAFAAgc2FsdEBwaHAtb3Bl
bnBncC5vcmdjMeQoM6PoBNaZCG9tU6culRW1CFpx9CZ+MiqDhX5YZAAAo50CCKFQCD3+lxvdxwLx
r2QwDCMixuMyDeycxUOuJZEl3hHQuB8/9Egx5uU/3mnQ6OYOzXF0j7nR7d5xFvEdeZDBadXkAgkB
QmJvtBo2u3bJwwWUE/NbIoqKGw/Z2Y2gfV+XUc0fQcVxZZ5UVM+dIbMt+AsCpVp8MBEZVkKCz6GN
Cgw4sYO19cI=
-----END PGP PRIVATE KEY BLOCK-----";

const string curve25519KeyData = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

xX0GaV9WrRsAAAAgl5jxx6tA0bhvuVQ0JtNc6mLYxFe1nuah3uG5BKAQVyT+HQkLAwjW2uFNUUcq
HeB34unioyqUeGoNBEhQLDfAFD0UnvSDpbG/pa/xHgMRL1xzUMTZbQf2wFoW5w7ldwJtSm97wRxe
28BEQ9DCJoQIAHtzJMK5Bh8bCAAAAFoFAmlfVq0iIQYlrWrkGkNBduPffiOkNDpg5O3rUJ96qIAD
Pl7d7n+qPQkQJa1q5BpDQXYCGwMDCwkHBCICAwEFFQgMCg4FFgABAgMCHgsLJwkCCQMHAgcDBwEA
AAAA0WAQD3W31tLyBPnT+5QXey1QknIz+L/Jw0eW37ku/7/qoI/Z/eTqu4hvcW9nXrc8G7CESo3V
u0qHwHZSlTMi9iAjZZkLEudxJ2Cv2mer/BQiLwDNKk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5u
djE5ODFAZ21haWwuY29tPsKVBhAbCAAAADYFAmlfVq0iIQYlrWrkGkNBduPffiOkNDpg5O3rUJ96
qIADPl7d7n+qPQkQJa1q5BpDQXYCGQEAAAAAKlEQ0kkWrxXLzIbjbCTxxftk3pfDWYOfIBdP3Or0
LbbsbVISTMaBOD99T07CO4///M9toCoRvK/0/JSB0JhUCYSsduIBcTdWTjwelUb9Olnt4A3NLE5n
dXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5udkBpd2F5dmlldG5hbS5jb20+wpIGEBsIAAAAMwUCaV9W
rSIhBiWtauQaQ0F2499+I6Q0OmDk7etQn3qogAM+Xt3uf6o9CRAlrWrkGkNBdgAAAACCxxCWbq7t
PQRWfOf57SQ34+u1v60MbqzLT3PyS3JtUkykqYflQRFO0jpCVBHc7tTdJEIG/TRb/7tq4NMucnyO
yA3d9G246Mztr5y8tZmzFxcoAMd9BmlfVq0ZAAAAIMKQKue43Od6iiOeMpJqrI8A9magV6jXScAq
x6tkknh//h0JCwMI97vzVeAftFXgpbNVMZqTtFSCE2F+moMCEfiDJuPmXMdZEAbioQ5/WOIiHDum
IgdAwwuoTLcAcn02dPgQwWfFop91mMtFb1RjZ9gwVX/ClQYYGwgAAAA2BQJpX1atIiEGJa1q5BpD
QXbj334jpDQ6YOTt61CfeqiAAz5e3e5/qj0JECWtauQaQ0F2AhsMAAAAAO6sEOi6ya624Tml5dxg
XErntEXIfFOXDGidsZQl8i9Bwlt2934sub/Dnm1r93FclTpnG7MkgD8MfIwB0W/JsFNzIv3CEKHa
lnXG0jd5yUXz3hkC1RPaZVBlH0pjKjBQ/I3Ym4K478js
-----END PGP PRIVATE KEY BLOCK-----";

const string curve448KeyData = @"-----BEGIN PGP PRIVATE KEY BLOCK-----

xa8GaV9WrRwAAAA5SS680HTEZsuA4jP4FmdaQVCYCQ9MtoEzGfZFG8Kz+CSafSuVu4yY/oBtUvn0
CdFRkRXSeUnQxHoA/h0JCwMIXGFItz5LJAfgzlp3cEzZBEcDtRpNazcRZlKpg+KeKG1Xin0ztvQm
iDtanmRUCx5sDgm5JEbmUoWG2nJcKHqaauFRVWhU5LZOkjN9GxLm0jKrlibCU97l2bIJaClnXMUx
230T5SVLwsA7Bh8cCgAAAFoFAmlfVq0iIQbvDsCJDBtc4dOTZXtD1k8h+fpARwPZAQY2gkrsM1Tf
VAkQ7w7AiQwbXOECGwMDCwkHBCICAwEFFQgMCg4FFgABAgMCHgsLJwkCCQMHAgcDBwEAAAAALOMg
QHv9xsd/B2+BeKQf18feIG4x/h8Wjev/9odKbBanJEwH5XOgqKP/vMbluIqfYY1CE19/fVvKzMOS
Jt3vVcveVUmxAJdgSXzZo4cei3G/DtZ+yIS/M/d6coBNV4HQs6D1xSSQkGXyk6MYI9ykc1cDXPPo
lYM+41Ull4HJPRo2LRE0EOsdpOLGJETKAdtsOp91GADNKk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5
ZW5udjE5ODFAZ21haWwuY29tPsLAFwYQHAoAAAA2BQJpX1atIiEG7w7AiQwbXOHTk2V7Q9ZPIfn6
QEcD2QEGNoJK7DNU31QJEO8OwIkMG1zhAhkBAAAAAMI0IPL3OjOSFNtQ5Pc0T7VRoaFFsMxexo+/
ALjpcawuk2b4Oi2tnCcmQZHiMrkW2cvedVZ1ccnCimw+lhOeFOuWbYpFUfklxLTBihdyktykA+xR
LHdxqs490AWAnKOtpy66TV9GwzlKIpIEXvSIRhfyn4AhpZo+Xh32chj36CWEt1E2BiMrvTjOpWmX
wC4+t82l7BkAzSxOZ3V5ZW4gVmFuIE5ndXllbiA8bmd1eWVubnZAaXdheXZpZXRuYW0uY29tPsLA
FAYQHAoAAAAzBQJpX1atIiEG7w7AiQwbXOHTk2V7Q9ZPIfn6QEcD2QEGNoJK7DNU31QJEO8OwIkM
G1zhAAAAAKsjIEIbShCAl3dPUVWwX1gg0vVLLSqnsfRXiUZUBhDvVNxcTwseBC/GucAZIF8zfKwZ
/zv8UmcU5zalUdXV0iOs3ZUnwB8v77YGQds+4vmUDUz6WvmqOrTXltQADlW5ZrPr+knBzbHGj+4U
HMOZtK/HxYivlCwiGE06Q5SKckLbBGWZDqqoC6kAVj1o0QmzTbuiLDcAx60GaV9WrRoAAAA4zDZ7
LWuuto5AGFMp69Aum9HyCUEA416iy0g3TyO+HvviHX0B54Iv6+s5hmp/rEkg85SnGVbD/Cf+HQkL
AwgNYjwnXq/7FuCdSu8k+Wl5ciePOfoUitjYDM7k2bOD3NZSJeZqq6dkRPkSgBr6wuudUqk5jjH0
bManmkVw+1ObqKnv7mUi4SaGdFbjgtFKo7xbvWxr+YUAzTcu1T9OxUEE0k1Ca8LAFwYYHAoAAAA2
BQJpX1atIiEG7w7AiQwbXOHTk2V7Q9ZPIfn6QEcD2QEGNoJK7DNU31QJEO8OwIkMG1zhAhsMAAAA
ABgjIJxPwgEZ/mLj3ZU4cFSKoznpuHzR9vNJlLsx5x4lRBUUgpMMrMCiQLteBiIDPy2ReT2yeXDx
xoIvgwV1794T5YB8W8O2RktpMQwutc83eAZPeSd69tA6tP2AO/wnBLQg4TavCp0m0pGwWhMgGvIp
e4V07IIPCwxoJJLRgOOY8VXm89IRlC9sE1TsaCcuqr6qzRsA1RiWqIKsuWu1j0r0ARc555CAxUAV
MF3mZ2k=
-----END PGP PRIVATE KEY BLOCK-----";

var rsaPrivateKey = OpenPgp.DecryptPrivateKey(rsaKeyData, passphrase);
var eccPrivateKey = OpenPgp.DecryptPrivateKey(eccKeyData, passphrase);
var curve25519PrivateKey = OpenPgp.DecryptPrivateKey(curve25519KeyData, passphrase);
var curve448PrivateKey = OpenPgp.DecryptPrivateKey(curve448KeyData, passphrase);

Console.WriteLine("Sign & encrypt literal data message with AES128 cipher:");
Config.PreferredSymmetric = SymmetricAlgorithm.Aes128;
var literalMessage = OpenPgp.CreateLiteralMessage(SecureRandom.GetNextBytes(new SecureRandom(), 10000));
var encryptedMessage = OpenPgp.Encrypt(
    literalMessage,
    [rsaPrivateKey.PublicKey, eccPrivateKey.PublicKey],
    [passphrase],
    [rsaPrivateKey, eccPrivateKey, curve25519PrivateKey, curve448PrivateKey]
);
var armored = encryptedMessage.Armor();
Console.WriteLine(armored);
Console.WriteLine();

Console.WriteLine("Decrypt with passphrase & verify signatures:");
literalMessage = OpenPgp.Decrypt(encryptedMessage, [], [passphrase]);
var verifications = literalMessage.Verify([
    rsaPrivateKey.PublicKey,
    eccPrivateKey.PublicKey,
    curve25519PrivateKey.PublicKey,
    curve448PrivateKey.PublicKey
]);
foreach (var verification in verifications)
{
    Console.WriteLine($"Key ID: {Hex.ToHexString(verification.KeyId)}");
    Console.WriteLine($"Signature is verified: {verification.IsVerified}");
    Console.WriteLine();
}

Console.WriteLine("Decrypt with rsa key & verify signatures:");
literalMessage = OpenPgp.Decrypt(encryptedMessage, [rsaPrivateKey], []);
verifications = literalMessage.Verify([
    rsaPrivateKey.PublicKey,
    eccPrivateKey.PublicKey,
    curve25519PrivateKey.PublicKey,
    curve448PrivateKey.PublicKey
]);
foreach (var verification in verifications)
{
    Console.WriteLine($"Key ID: {Hex.ToHexString(verification.KeyId)}");
    Console.WriteLine($"Signature is verified: {verification.IsVerified}");
    Console.WriteLine();
}

Console.WriteLine("Decrypt with ecc key & verify signatures:");
literalMessage = OpenPgp.Decrypt(encryptedMessage, [eccPrivateKey], []);
verifications = literalMessage.Verify([
    rsaPrivateKey.PublicKey,
    eccPrivateKey.PublicKey,
    curve25519PrivateKey.PublicKey,
    curve448PrivateKey.PublicKey
]);
foreach (var verification in verifications)
{
    Console.WriteLine($"Key ID: {Hex.ToHexString(verification.KeyId)}");
    Console.WriteLine($"Signature is verified: {verification.IsVerified}");
    Console.WriteLine();
}

Console.WriteLine("Sign & encrypt literal data message with AEAD AES256 cipher:");
Config.PreferredSymmetric = SymmetricAlgorithm.Aes256;
literalMessage = OpenPgp.CreateLiteralMessage(SecureRandom.GetNextBytes(new SecureRandom(), 10000));
encryptedMessage = OpenPgp.Encrypt(
    literalMessage, [curve25519PrivateKey.PublicKey, curve448PrivateKey.PublicKey], [passphrase],
    [rsaPrivateKey, eccPrivateKey, curve25519PrivateKey, curve448PrivateKey]
);
armored = encryptedMessage.Armor();
Console.WriteLine(armored);
Console.WriteLine();

Console.WriteLine("Decrypt with curve25519 key & verify signatures:");
literalMessage = OpenPgp.Decrypt(encryptedMessage, [curve25519PrivateKey], []);
verifications = literalMessage.Verify([
    rsaPrivateKey.PublicKey,
    eccPrivateKey.PublicKey,
    curve25519PrivateKey.PublicKey,
    curve448PrivateKey.PublicKey
]);
foreach (var verification in verifications)
{
    Console.WriteLine($"Key ID: {Hex.ToHexString(verification.KeyId)}");
    Console.WriteLine($"Signature is verified: {verification.IsVerified}");
    Console.WriteLine();
}

Console.WriteLine("Decrypt with curve448 key & verify signatures:");
literalMessage = OpenPgp.Decrypt(encryptedMessage, [curve448PrivateKey], []);
verifications = literalMessage.Verify([
    rsaPrivateKey.PublicKey,
    eccPrivateKey.PublicKey,
    curve25519PrivateKey.PublicKey,
    curve448PrivateKey.PublicKey
]);
foreach (var verification in verifications)
{
    Console.WriteLine($"Key ID: {Hex.ToHexString(verification.KeyId)}");
    Console.WriteLine($"Signature is verified: {verification.IsVerified}");
    Console.WriteLine();
}

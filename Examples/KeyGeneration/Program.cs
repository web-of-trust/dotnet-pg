using DotNetPG;
using DotNetPG.Common;
using DotNetPG.Enum;

IList<string> userIDs = [
    "Nguyen Van Nguyen <nguyennv1981@gmail.com>",
    "Nguyen Van Nguyen <nguyennv@iwayvietnam.com>",
];
var passphrase = Helper.GeneratePassword();
Console.WriteLine($"Generate passphrase: {passphrase}");

Console.WriteLine("Generate RSA private key");
var rsaKey = OpenPGP.GenerateKey(userIDs, passphrase, KeyType.Rsa);
Console.WriteLine(rsaKey.Armor());
Console.WriteLine();

Console.WriteLine("Generate Ecc private key");
var eccKey = OpenPGP.GenerateKey(userIDs, passphrase, KeyType.Ecc);
Console.WriteLine(eccKey.Armor());
Console.WriteLine();

Console.WriteLine("Generate Curve25519 private key");
var curve25519Key = OpenPGP.GenerateKey(userIDs, passphrase, KeyType.Curve25519);
Console.WriteLine(curve25519Key.Armor());
Console.WriteLine();

Console.WriteLine("Generate Curve448 private key");
var curve448Key = OpenPGP.GenerateKey(userIDs, passphrase, KeyType.Curve448);
Console.WriteLine(curve448Key.Armor());
Console.WriteLine();

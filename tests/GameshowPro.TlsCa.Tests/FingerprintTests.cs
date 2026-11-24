namespace GameshowPro.TlsCa.Tests;

[TestClass]
public sealed class FingerprintTests
{
    [TestMethod]
    public void Sha256_IsUpperCaseHexPairsJoinedByColons()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        byte[] hash = SHA256.HashData(identity.Ca.RawData);
        string expected = string.Join(":", hash.Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));

        string fingerprint = Fingerprint.Sha256(identity.Ca);

        Assert.AreEqual(expected, fingerprint);
        Assert.AreEqual(95, fingerprint.Length);
        Assert.AreEqual(fingerprint, Fingerprint.Sha256(identity.Ca.RawData));
        Assert.AreEqual(fingerprint.ToUpperInvariant(), fingerprint);
    }

    [TestMethod]
    public void Sha256_KnownValue()
    {
        // SHA-256 of the empty input.
        Assert.AreEqual(
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55",
            Fingerprint.Sha256([]));
    }
}

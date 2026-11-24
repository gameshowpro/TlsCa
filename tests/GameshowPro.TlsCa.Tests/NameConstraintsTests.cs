namespace GameshowPro.TlsCa.Tests;

/// <summary>
/// Acceptance test 2: the nameConstraints value equals the Part 1 structure byte for byte. Every expected value is
/// written out by hand from that structure, never produced by an ASN.1 encoder.
/// </summary>
[TestClass]
public sealed class NameConstraintsTests
{
    // excludedSubtrees [1] { GeneralSubtree { iPAddress [7] 8 zero bytes }, GeneralSubtree { iPAddress [7] 32 zero bytes } }
    private static readonly byte[] s_excludedSubtrees =
    [
        0xA1, 0x30,
              0x30, 0x0A,
                    0x87, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x30, 0x22,
                    0x87, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    [TestMethod]
    public void Encode_ShortName_MatchesHandBuiltStructure()
    {
        byte[] expected =
        [
            0x30, 0x48,                                   // NameConstraints SEQUENCE, 72 bytes
                  0xA0, 0x14,                             // permittedSubtrees [0], 20 bytes
                        0x30, 0x12,                       // GeneralSubtree SEQUENCE, 18 bytes
                              0x82, 0x10,                 // dNSName [2], 16 bytes: "gsp-a1b2c3.local"
                                    0x67, 0x73, 0x70, 0x2D, 0x61, 0x31, 0x62, 0x32,
                                    0x63, 0x33, 0x2E, 0x6C, 0x6F, 0x63, 0x61, 0x6C,
                  .. s_excludedSubtrees,                  // excludedSubtrees [1], 48 bytes
        ];

        CollectionAssert.AreEqual(expected, CertificateProfiles.EncodeNameConstraints("gsp-a1b2c3.local"));
    }

    [TestMethod]
    public void Encode_LongestName_MatchesHandBuiltStructure()
    {
        // A 63-character label: the longest name still uses single-byte (short form) lengths throughout.
        string label = new string('a', 51) + "-triggergate";
        Assert.AreEqual(63, label.Length);
        byte[] expected =
        [
            0x30, 0x7D,                                   // 125 bytes
                  0xA0, 0x49,                             // 73 bytes
                        0x30, 0x47,                       // 71 bytes
                              0x82, 0x45,                 // 69 bytes
                                    .. Encoding.ASCII.GetBytes(label + ".local"),
                  .. s_excludedSubtrees,
        ];

        CollectionAssert.AreEqual(expected, CertificateProfiles.EncodeNameConstraints(label + ".local"));
    }

    [TestMethod]
    public void CaCertificate_CarriesCriticalNameConstraintsWithHandBuiltValue()
    {
        using DeviceIdentity identity = TestPki.CreateIdentity(TestPki.Name, TestPki.Now);
        byte[] expected =
        [
            0x30, 0x53,                                   // 83 bytes
                  0xA0, 0x1F,                             // 31 bytes
                        0x30, 0x1D,                       // 29 bytes
                              0x82, 0x1B,                 // 27 bytes: "studio-pc-triggergate.local"
                                    0x73, 0x74, 0x75, 0x64, 0x69, 0x6F, 0x2D, 0x70, 0x63, 0x2D,
                                    0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x67, 0x61, 0x74, 0x65,
                                    0x2E, 0x6C, 0x6F, 0x63, 0x61, 0x6C,
                  .. s_excludedSubtrees,
        ];

        X509Extension extension = identity.Ca.Extensions.Single(e => e.Oid?.Value == "2.5.29.30");
        Assert.IsTrue(extension.Critical);
        CollectionAssert.AreEqual(expected, extension.RawData);
        Assert.IsFalse(identity.Leaf.Extensions.Any(e => e.Oid?.Value == "2.5.29.30"), "Only the CA carries name constraints.");
    }

    [TestMethod]
    [DataRow("gsp-a1b2c3")]
    [DataRow("gsp-a1b2c3.local.")]
    [DataRow("gsp-a1b2c3.example")]
    [DataRow("GSP-A1B2C3.local")]
    [DataRow(".local")]
    [DataRow("-gsp.local")]
    [DataRow("a.b.local")]
    public void Encode_RejectsAnythingButOneValidLabelDotLocal(string mdnsName) =>
        _ = Assert.ThrowsExactly<ArgumentException>(() => CertificateProfiles.EncodeNameConstraints(mdnsName));
}

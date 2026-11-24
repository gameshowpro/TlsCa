namespace GameshowPro.TlsCa.Tests;

/// <summary>Acceptance test 5: derivation, truncation, invalid characters, empty host.</summary>
[TestClass]
public sealed class DeviceNameTests
{
    [TestMethod]
    [DataRow("studio-pc", "triggergate", "studio-pc-triggergate", DisplayName = "Plain")]
    [DataRow("STUDIO-PC", "TriggerGate", "studio-pc-triggergate", DisplayName = "Lower-cased")]
    [DataRow("Studio PC_01.lan", "trigger gate", "studio-pc-01-lan-trigger-gate", DisplayName = "Invalid characters become hyphens")]
    [DataRow("a---b", "x__-  y", "a-b-x-y", DisplayName = "Runs collapse")]
    [DataRow("--host--", "-.app.-", "host-app", DisplayName = "Leading and trailing hyphens trimmed per part")]
    [DataRow("Café", "Ünïcode", "caf-n-code", DisplayName = "Non-ASCII letters become hyphens")]
    [DataRow("Kelvin", "app", "elvin-app", DisplayName = "Only ASCII letters are lower-cased")]
    [DataRow("", "triggergate", "gsp-triggergate", DisplayName = "Empty host")]
    [DataRow("___", "triggergate", "gsp-triggergate", DisplayName = "Host with no usable characters")]
    public void Derive_AppliesNamingRules(string host, string app, string expected)
    {
        string name = DeviceName.Derive(host, app);

        Assert.AreEqual(expected, name);
        Assert.IsTrue(DeviceName.IsValidLabel(name));
    }

    [TestMethod]
    public void Derive_TooLong_TruncatesHostAndKeepsAppWhole()
    {
        string name = DeviceName.Derive(new string('h', 80), "triggergate");

        Assert.AreEqual(new string('h', 51) + "-triggergate", name);
        Assert.AreEqual(63, name.Length);
    }

    [TestMethod]
    public void Derive_TruncationEndingOnHyphen_TrimsIt()
    {
        // The host is cut after 51 characters, which ends on its hyphen.
        string name = DeviceName.Derive(new string('a', 50) + "-" + new string('b', 20), "triggergate");

        Assert.AreEqual(new string('a', 50) + "-triggergate", name);
        Assert.IsTrue(DeviceName.IsValidLabel(name));
    }

    [TestMethod]
    public void Derive_ExactlySixtyThree_IsNotTruncated()
    {
        string host = new('h', 51);

        Assert.AreEqual(host + "-triggergate", DeviceName.Derive(host, "triggergate"));
    }

    [TestMethod]
    public void Derive_LongestAppLabel_LeavesOneHostCharacter()
    {
        string app = new('x', 61);

        Assert.AreEqual("s-" + app, DeviceName.Derive("studio-pc", app));
    }

    [TestMethod]
    [DataRow("", DisplayName = "Empty")]
    [DataRow("---", DisplayName = "Hyphens only")]
    [DataRow("!!!", DisplayName = "No usable characters")]
    [DataRow("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", DisplayName = "62 characters")]
    public void Derive_UnusableAppLabel_Throws(string app) =>
        _ = Assert.ThrowsExactly<ArgumentException>(() => DeviceName.Derive("studio-pc", app));

    [TestMethod]
    [DataRow("a", true)]
    [DataRow("studio-pc-triggergate", true)]
    [DataRow("0-9", true)]
    [DataRow("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true, DisplayName = "63 characters")]
    [DataRow("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", false, DisplayName = "64 characters")]
    [DataRow("", false)]
    [DataRow(null, false)]
    [DataRow("-a", false)]
    [DataRow("a-", false)]
    [DataRow("Studio", false)]
    [DataRow("a.local", false)]
    [DataRow("a_b", false)]
    [DataRow("a b", false)]
    public void IsValidLabel(string? label, bool expected) => Assert.AreEqual(expected, DeviceName.IsValidLabel(label));

    [TestMethod]
    public void ToMdnsName_AppendsLocal()
    {
        Assert.AreEqual("studio-pc-triggergate.local", DeviceName.ToMdnsName("studio-pc-triggergate"));
        _ = Assert.ThrowsExactly<ArgumentException>(() => DeviceName.ToMdnsName("Not valid"));
    }
}

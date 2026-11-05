// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsMaterial;

public class when_refusing_invalid_material
{
    [Theory]
    [InlineData("missing-certificate")]
    [InlineData("missing-key")]
    [InlineData("unreadable")]
    [InlineData("malformed")]
    [InlineData("mismatched")]
    [InlineData("expired")]
    [InlineData("wrong-eku")]
    [InlineData("empty-bundle")]
    public void should_refuse_without_disclosing_file_contents(string scenario)
    {
        using var certificates = new given.TestCertificates();
        var settings = certificates.Settings;
        switch (scenario)
        {
            case "missing-certificate": settings.ClientCertificate!.CertificatePath = string.Empty; break;
            case "missing-key": settings.ClientCertificate!.KeyPath = string.Empty; break;
            case "unreadable": settings.ClientCertificate!.KeyPath += ".absent"; break;
            case "malformed": File.WriteAllText(certificates.CertificatePath, "not a certificate"); break;
            case "mismatched":
                using (var other = certificates.Issue(client: true)) File.WriteAllText(certificates.CertificatePath, other.ExportCertificatePem());
                break;
            case "expired":
                using (var expired = certificates.Issue(client: true, expired: true)) certificates.WriteClient(expired);
                break;
            case "wrong-eku":
                using (var server = certificates.Issue()) certificates.WriteClient(server);
                break;
            case "empty-bundle": File.WriteAllText(certificates.BundlePath, string.Empty); break;
        }

        BackendTlsMaterial.TryLoad(settings, DateTimeOffset.UtcNow, out var material, out var problem).ShouldBeFalse();
        material.ShouldBeNull();
        problem!.ShouldContain("Cratis:AuthProxy:BackendTls:");
        problem.ShouldNotContain(certificates.CertificatePath);
        problem.ShouldNotContain("BEGIN");
    }
}

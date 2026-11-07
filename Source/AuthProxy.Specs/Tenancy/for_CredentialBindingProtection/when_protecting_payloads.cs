// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Tenancy.for_CredentialBindingProtection;

public class when_protecting_payloads : Specification
{
    [Theory]
    [InlineData("", "", "Cratis.AuthProxy")]
    [InlineData("direct-api", "staging", "Cratis.AuthProxy;resource=direct-api;environment=staging")]
    [InlineData("", "staging", "Cratis.AuthProxy;environment=staging")]
    [InlineData("direct-api", "", "Cratis.AuthProxy;resource=direct-api")]
    public void should_only_change_the_application_name_when_opted_in(string resource, string environment, string name) =>
        CredentialBindingProtection.ApplicationName(Configuration(resource, environment)).ShouldEqual(name);

    [Theory]
    [InlineData("direct-api", "staging", true)]
    [InlineData("direct-api", "production", false)]
    [InlineData("another-api", "staging", false)]
    [InlineData("direct-api", "Staging", false)]
    [InlineData("", "", false)]
    public void should_only_unprotect_with_the_same_binding(string resource, string environment, bool allowed)
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var staging = DataProtectionProvider.Create(directory, builder => builder.SetApplicationName(CredentialBindingProtection.ApplicationName(Configuration("direct-api", "staging"))));
            var target = DataProtectionProvider.Create(directory, builder => builder.SetApplicationName(CredentialBindingProtection.ApplicationName(Configuration(resource, environment))));
            var payload = staging.CreateProtector("session").Protect("test payload");
            if (allowed) target.CreateProtector("session").Unprotect(payload).ShouldEqual("test payload");
            else Assert.Throws<CryptographicException>(() => target.CreateProtector("session").Unprotect(payload));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    static IConfiguration Configuration(string resource, string environment) => new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:CredentialBinding:Resource"] = resource,
        [$"{C.AuthProxy.SectionKey}:CredentialBinding:Environment"] = environment,
    }).Build();
}

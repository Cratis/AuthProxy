// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.for_CredentialBinding;

/// <summary>Shared keys need an explicit deployment resource boundary.</summary>
/// <param name="harness">The deployment used to capture startup warnings.</param>
[Collection(TwoTenantPersonSpecCollection.Name)]
public class when_a_shared_key_ring_is_configured(TwoTenantPersonHarness harness)
{
    [Theory]
    [InlineData(null, "", false)]
    [InlineData("DataProtectionKeysPath", "", true)]
    [InlineData("DataProtection:Store", "", true)]
    [InlineData("DataProtectionKeysPath", "direct-api", false)]
    [InlineData("DataProtection:Store", "direct-api", false)]
    public void should_warn_only_when_a_configured_ring_has_no_resource(string? setting, string resource, bool expected)
    {
        var logs = new CapturedLogs();
        var keysPath = Path.Combine(Path.GetTempPath(), $"authproxy-binding-{Guid.NewGuid():N}");
        var settings = new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:CredentialBinding:Resource"] = resource,
        };
        if (setting is not null)
        {
            settings[$"{C.AuthProxy.SectionKey}:{setting}"] = setting == "DataProtectionKeysPath" ? keysPath : "FileSystem";
        }

        try
        {
            using var deployment = harness.WithWebHostBuilder(builder => builder
                .ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(settings))
                .ConfigureLogging(logging => logging.AddProvider(logs)));
            using var client = deployment.CreateClient();
            Assert.Equal(expected, logs.Mentioning("key ring", "CredentialBinding.Resource"));
        }
        finally
        {
            if (Directory.Exists(keysPath)) Directory.Delete(keysPath, recursive: true);
        }
    }
}

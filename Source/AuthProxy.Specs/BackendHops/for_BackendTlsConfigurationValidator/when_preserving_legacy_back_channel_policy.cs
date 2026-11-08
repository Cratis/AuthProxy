// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsConfigurationValidator;

public class when_preserving_legacy_back_channel_policy
{
    [Theory]
    [InlineData(false, false, false, "http://verifier.example/verify", true)]
    [InlineData(false, true, false, "http://verifier.example/verify", false)]
    [InlineData(false, true, true, "http://verifier.example/verify", true)]
    [InlineData(false, false, true, "http://verifier.example/verify", true)]
    [InlineData(false, true, true, "ftp://verifier.example/verify", true)]
    [InlineData(true, false, true, "http://verifier.example/verify", false)]
    [InlineData(true, true, true, "http://verifier.example/verify", false)]
    [InlineData(true, false, true, "http://localhost/verify", true)]
    [InlineData(true, true, true, "http://127.0.0.1/verify", true)]
    [InlineData(true, true, true, "http://[::1]/verify", true)]
    [InlineData(true, false, false, "http://localhost/verify", false)]
    [InlineData(true, true, false, "http://127.0.0.1/verify", false)]
    [InlineData(true, true, true, "ftp://localhost/verify", false)]
    [InlineData(true, true, false, "https://verifier.example/verify", true)]
    public void should_apply_the_same_policy_at_startup_and_at_runtime(bool requireTls, bool signing, bool localDevelopment, string address, bool allowed)
    {
        var configuration = new C.AuthProxy
        {
            Profile = localDevelopment ? C.DeploymentProfile.LocalDevelopment : C.DeploymentProfile.Default,
            BackendTls = new() { RequireTlsOnIdentityHops = requireTls },
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = signing ? new() : null } },
            Admission = new() { Capability = new() { VerifierUrl = address } }
        };
        BackendHopHosts.AllowsIdentityBackChannel(configuration, address).ShouldEqual(allowed);
        var result = new BackendTlsConfigurationValidator(TimeProvider.System).Validate(null, configuration);
        (result.Failures?.Any(failure => failure.StartsWith("Cratis:AuthProxy:Admission:Capability:VerifierUrl", StringComparison.Ordinal)) ?? false).ShouldEqual(!allowed);
    }
}

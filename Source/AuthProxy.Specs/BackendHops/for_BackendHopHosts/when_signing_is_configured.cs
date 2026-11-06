// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendHopHosts;

public class when_signing_is_configured : Specification
{
    IReadOnlySet<string> _hosts;

    void Because() => _hosts = BackendHopHosts.For(new()
    {
        Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://app.example" }, ForwardedIdentity = new() } },
        Invite = new() { StageUrl = "https://stage.example/stage", ExchangeUrl = "https://invite.example/exchange" },
        Link = new() { ExchangeUrl = "https://link.example/exchange" },
        SignIn = new() { NotifyUrl = "https://notify.example/notify" },
        Admission = new() { Capability = new() { VerifierUrl = "https://verifier.example/verify" } },
        TenantVerification = new() { UrlTemplate = "https://tenants.example/{tenantId}" },
        TenantResolutions = [new() { Options = new Tenancy.SubHostOptions { VerificationUrlTemplate = "https://subhost.example/{tenantId}" } }]
    });

    [Fact] void should_include_invitation_staging() => _hosts.Contains("stage.example").ShouldBeTrue();
    [Fact] void should_include_invitation_exchange() => _hosts.Contains("invite.example").ShouldBeTrue();
    [Fact] void should_include_link_exchange() => _hosts.Contains("link.example").ShouldBeTrue();
    [Fact] void should_include_sign_in_notification() => _hosts.Contains("notify.example").ShouldBeTrue();
    [Fact] void should_exclude_capability_verification() => _hosts.Contains("verifier.example").ShouldBeFalse();
    [Fact] void should_exclude_tenant_verification() => _hosts.Contains("tenants.example").ShouldBeFalse();
    [Fact] void should_exclude_subhost_verification() => _hosts.Contains("subhost.example").ShouldBeFalse();
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsHttpClientPolicy;

public class when_identity_back_channels_are_configured : given.a_tls_policy
{
    void Establish()
    {
        configuration.Services["app"].ForwardedIdentity = new();
        configuration.Invite = new() { StageUrl = "https://stage.example/stage", ExchangeUrl = "https://invite.example/exchange" };
        configuration.Link = new() { ExchangeUrl = "https://link.example/exchange" };
        configuration.SignIn = new() { NotifyUrl = "https://notify.example/notify" };
        configuration.Admission = new() { Capability = new() { VerifierUrl = "https://verifier.example/verify" } };
        configuration.TenantVerification = new() { UrlTemplate = "https://tenants.example/{tenantId}" };
    }

    [Fact] void should_offer_the_certificate_to_invitation_staging() => policy.SelectClientCertificate("stage.example")!.HasPrivateKey.ShouldBeTrue();
    [Fact] void should_offer_the_certificate_to_invitation_exchange() => policy.SelectClientCertificate("invite.example")!.HasPrivateKey.ShouldBeTrue();
    [Fact] void should_offer_the_certificate_to_link_exchange() => policy.SelectClientCertificate("link.example")!.HasPrivateKey.ShouldBeTrue();
    [Fact] void should_offer_the_certificate_to_sign_in_notification() => policy.SelectClientCertificate("notify.example")!.HasPrivateKey.ShouldBeTrue();
    [Fact] void should_offer_the_certificate_to_a_capability_verifier() => policy.SelectClientCertificate("verifier.example")!.HasPrivateKey.ShouldBeTrue();
    [Fact] void should_offer_the_certificate_to_a_tenant_verifier() => policy.SelectClientCertificate("tenants.example")!.HasPrivateKey.ShouldBeTrue();
}

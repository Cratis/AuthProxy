// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_CratisIdentityProfile;

public class when_registering_the_profile : given.a_cratis_identity_realm
{
    OpenIdConnectOptions _options;
    C.OidcProvider _provider;

    void Because()
    {
        _options = _services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(Scheme);
        _provider = _services.GetRequiredService<IOptionsMonitor<C.Authentication>>().CurrentValue.OidcProviders[0];
    }

    [Fact] void should_use_pkce() => _options.UsePkce.ShouldBeTrue();
    [Fact] void should_be_a_confidential_client() => _options.ClientSecret.ShouldEqual(ClientSecret);
    [Fact] void should_require_https_metadata() => _options.RequireHttpsMetadata.ShouldBeTrue();
    [Fact] void should_verify_the_discovered_issuer() => _options.ConfigurationManager.ShouldNotBeNull();
    [Fact] void should_keep_protocol_claim_names() => _options.MapInboundClaims.ShouldBeFalse();
    [Fact] void should_map_the_subject_to_the_canonical_identity() => _provider.CanonicalIdentity!.SubjectClaimType.ShouldEqual("sub");
    [Fact] void should_key_the_canonical_identity_by_the_scheme() => _provider.CanonicalIdentity!.ProviderKey.ShouldEqual(Scheme);
}

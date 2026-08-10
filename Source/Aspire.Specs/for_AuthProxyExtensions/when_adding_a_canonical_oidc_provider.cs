// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.given;

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_adding_a_canonical_oidc_provider : an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithCanonicalOidcProvider(
        "Microsoft Entra",
        OidcProviderType.Microsoft,
        "https://login.microsoftonline.com/tenant/v2.0",
        "client-id",
        "client-secret",
        "entra-workforce",
        "oid");

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_emit_the_provider_key() => _environment["Cratis__AuthProxy__Authentication__OidcProviders__0__CanonicalIdentity__ProviderKey"].ShouldEqual("entra-workforce");
    [Fact] void should_emit_the_subject_claim_type() => _environment["Cratis__AuthProxy__Authentication__OidcProviders__0__CanonicalIdentity__SubjectClaimType"].ShouldEqual("oid");
    [Fact] void should_preserve_the_existing_provider_configuration() => _environment["Cratis__AuthProxy__Authentication__OidcProviders__0__Name"].ShouldEqual("Microsoft Entra");
}

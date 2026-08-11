// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The route binding is the RFC 9449 <c>htu</c>, which is the target's path — the query is deliberately not
/// part of it. A notify URL that carries one therefore signs a route it does not fully name, and a captured
/// notification could be replayed against a different query while a conformant verifier still accepted it.
/// The only place that can be ruled out is where the endpoint is configured.
/// </summary>
public class and_the_notify_url_carries_a_query : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _withQuery;
    ValidateOptionsResult _withoutQuery;

    void Because()
    {
        _withQuery = Validate(Configuration($"{NotifyUrl}?tenant=acme", signingKeys: PrivateKey("current")));
        _withoutQuery = Validate(Configuration(NotifyUrl, signingKeys: PrivateKey("current")));
    }

    [Fact] void should_reject_an_endpoint_carrying_a_query() => _withQuery.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_the_same_endpoint_without_one() => _withoutQuery.Succeeded.ShouldBeTrue();
}

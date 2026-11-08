// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>The claims AuthProxy verified travel in the signed body, under their exact names.</summary>
public class and_the_token_was_validated : a_verified_claims_sign_in_notifier
{
    JsonElement _claims;
    bool _present;

    async Task Because()
    {
        TheHandlerValidated(
            Scheme,
            ("iss", "https://idp.example.com"),
            ("sub", "0b8f6f1e-0000-4000-8000-000000000001"),
            ("idp", "github"),
            ("idp_sub", "gh-777"),
            ("github_id", "777"),
            ("auth_time", 1700000000L),
            ("jti", "token-1"));
        await _notifier.Notify(_httpContext, _principal, Scheme);
        _present = PostedVerifiedClaims(out _claims);
    }

    [Fact] void should_include_the_verified_claims() => _present.ShouldBeTrue();
    [Fact] void should_carry_the_issuer() => _claims.GetProperty("iss").GetString().ShouldEqual("https://idp.example.com");
    [Fact] void should_carry_the_account_subject() => _claims.GetProperty("sub").GetString().ShouldEqual("0b8f6f1e-0000-4000-8000-000000000001");
    [Fact] void should_carry_the_identity_provider() => _claims.GetProperty("idp").GetString().ShouldEqual("github");
    [Fact] void should_carry_the_identity_provider_subject() => _claims.GetProperty("idp_sub").GetString().ShouldEqual("gh-777");
    [Fact] void should_carry_the_external_account_id() => _claims.GetProperty("github_id").GetString().ShouldEqual("777");
    [Fact] void should_carry_the_authentication_time_as_a_number() => _claims.GetProperty("auth_time").GetInt64().ShouldEqual(1700000000L);
    [Fact] void should_carry_the_token_id() => _claims.GetProperty("jti").GetString().ShouldEqual("token-1");
    [Fact] void should_carry_nothing_else() => _claims.EnumerateObject().Count().ShouldEqual(7);
    [Fact] void should_bind_the_claims_into_the_signed_body() => Claim(Read(_handler.LastRequestAuthorization!.Parameter!), SignInAttestationClaims.BodyHash).ShouldEqual(Digest(_handler.LastRequestBytes.ToArray()));
    [Fact] void should_keep_the_existing_fields() => PostedBody().GetProperty("subject").GetString().ShouldEqual("subject-123");
}

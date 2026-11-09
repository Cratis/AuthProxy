// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>A claim that belongs to one token is ignored when it appears in the other.</summary>
public class and_claims_are_injected_into_the_wrong_token : a_verified_claims_sign_in_notifier
{
    JsonElement _claims;

    async Task Because()
    {
        TheHandlerValidated(
            Scheme,
            [("iss", "https://idp.example.com"), ("sub", "acct-1"), ("github_id", "injected"), ("idp", "injected"), ("idp_sub", "injected")],
            [("sub", "acct-1"), ("github_id", "777"), ("iss", "https://evil.example.com"), ("auth_time", 5L), ("jti", "injected")]);
        await _notifier.Notify(_httpContext, _principal, Scheme);
        PostedVerifiedClaims(out _claims);
    }

    [Fact] void should_take_the_external_account_id_from_the_access_token() => _claims.GetProperty("github_id").GetString().ShouldEqual("777");
    [Fact] void should_ignore_the_identity_provider_in_the_identity_token() => _claims.TryGetProperty("idp", out _).ShouldBeFalse();
    [Fact] void should_ignore_the_identity_provider_subject_in_the_identity_token() => _claims.TryGetProperty("idp_sub", out _).ShouldBeFalse();
    [Fact] void should_take_the_issuer_from_the_identity_token() => _claims.GetProperty("iss").GetString().ShouldEqual("https://idp.example.com");
    [Fact] void should_ignore_the_authentication_time_in_the_access_token() => _claims.TryGetProperty("auth_time", out _).ShouldBeFalse();
    [Fact] void should_ignore_the_token_id_in_the_access_token() => _claims.TryGetProperty("jti", out _).ShouldBeFalse();
}

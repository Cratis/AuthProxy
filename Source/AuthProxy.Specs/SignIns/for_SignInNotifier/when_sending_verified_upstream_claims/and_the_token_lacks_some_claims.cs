// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>A claim the validated token does not carry is omitted — never defaulted, never taken from elsewhere.</summary>
public class and_the_token_lacks_some_claims : a_verified_claims_sign_in_notifier
{
    JsonElement _claims;

    protected override ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
    [
        new Claim("sub", "subject-123"),
        new Claim("github_id", "from-the-session-principal"),
        new Claim("idp", "from-the-session-principal"),
    ],
    "github"));

    async Task Because()
    {
        TheHandlerValidated(Scheme, ("iss", "https://idp.example.com"), ("sub", "acct-1"));
        await _notifier.Notify(_httpContext, _principal, Scheme);
        PostedVerifiedClaims(out _claims);
    }

    [Fact] void should_carry_what_was_verified() => _claims.GetProperty("iss").GetString().ShouldEqual("https://idp.example.com");
    [Fact] void should_omit_the_external_account_id() => _claims.TryGetProperty("github_id", out _).ShouldBeFalse();
    [Fact] void should_omit_the_identity_provider() => _claims.TryGetProperty("idp", out _).ShouldBeFalse();
    [Fact] void should_omit_the_authentication_time() => _claims.TryGetProperty("auth_time", out _).ShouldBeFalse();
    [Fact] void should_omit_the_token_id() => _claims.TryGetProperty("jti", out _).ShouldBeFalse();
    [Fact] void should_not_copy_claims_from_the_session_principal() => _claims.EnumerateObject().Count().ShouldEqual(2);
}

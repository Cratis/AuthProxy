// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>A value with leading or trailing whitespace is omitted, not trimmed and forwarded.</summary>
public class and_a_value_has_surrounding_whitespace : a_verified_claims_sign_in_notifier
{
    JsonElement _claims;

    async Task Because()
    {
        TheHandlerValidated(Scheme, ("iss", " https://idp.example.com"), ("sub", "acct-1"), ("github_id", "777 "), ("idp", "github"));
        await _notifier.Notify(_httpContext, _principal, Scheme);
        PostedVerifiedClaims(out _claims);
    }

    [Fact] void should_omit_the_padded_issuer() => _claims.TryGetProperty("iss", out _).ShouldBeFalse();
    [Fact] void should_omit_the_padded_external_account_id() => _claims.TryGetProperty("github_id", out _).ShouldBeFalse();
    [Fact] void should_keep_the_clean_claims() => _claims.GetProperty("idp").GetString().ShouldEqual("github");
}

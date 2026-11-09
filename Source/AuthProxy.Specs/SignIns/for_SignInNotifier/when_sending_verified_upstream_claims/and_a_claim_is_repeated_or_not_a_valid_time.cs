// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Json;
using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.when_sending_verified_upstream_claims;

/// <summary>An ambiguous claim cannot be called verified: repeated values and a non-numeric time are omitted.</summary>
public class and_a_claim_is_repeated_or_not_a_valid_time : a_verified_claims_sign_in_notifier
{
    JsonElement _claims;

    async Task Because()
    {
        TheHandlerValidated(Scheme, ("sub", "acct-1"), ("idp", new[] { "github", "google" }), ("auth_time", "yesterday"));
        await _notifier.Notify(_httpContext, _principal, Scheme);
        PostedVerifiedClaims(out _claims);
    }

    [Fact] void should_keep_the_unambiguous_claim() => _claims.GetProperty("sub").GetString().ShouldEqual("acct-1");
    [Fact] void should_omit_the_repeated_claim() => _claims.TryGetProperty("idp", out _).ShouldBeFalse();
    [Fact] void should_omit_the_malformed_time() => _claims.TryGetProperty("auth_time", out _).ShouldBeFalse();
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier;

public class when_notifying_a_canonical_identity : a_canonical_sign_in_notifier
{
    SignInNotificationResult _result;

    protected override C.AuthProxy CreateConfig() => new()
    {
        SignIn = new C.SignIn { NotifyUrl = NotifyUrl },
        Authentication = new C.Authentication
        {
            OAuthProviders =
            [
                new C.OAuthProvider
                {
                    Name = "GitHub",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = "workforce",
                        SubjectClaimType = "oid",
                        Issuer = "https://identity.example.com/"
                    }
                }
            ]
        }
    };

    protected override ClaimsPrincipal CreatePrincipal() => new(new ClaimsIdentity(
    [
        new Claim("oid", "configured-subject"),
        new Claim("sub", "old-sub"),
    ],
    "github"));

    async Task Because() => _result = await _notifier.Notify(_httpContext, _principal);

    [Fact] void should_notify() => _result.ShouldEqual(SignInNotificationResult.Notified);
    [Fact] void should_post_the_configured_subject() => _handler.LastRequestBody!.ShouldContain("\"subject\":\"configured-subject\"");
    [Fact] void should_post_the_provider_key() => _handler.LastRequestBody!.ShouldContain("\"providerKey\":\"workforce\"");
    [Fact] void should_post_the_normalized_issuer() => _handler.LastRequestBody!.ShouldContain("\"issuer\":\"https://identity.example.com\"");
    [Fact] void should_not_post_an_old_fallback_subject() => _handler.LastRequestBody!.ShouldNotContain("old-sub");
}

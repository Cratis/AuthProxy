// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier;

public class when_notifying_a_canonical_oidc_callback : given.a_canonical_sign_in_notifier
{
    SignInNotificationResult _result;

    protected override C.AuthProxy CreateConfig() => new()
    {
        SignIn = new C.SignIn { NotifyUrl = NotifyUrl },
        Authentication = CanonicalOidcFixture.Configuration(),
    };

    protected override ClaimsPrincipal CreatePrincipal() => CanonicalOidcFixture.Principal();

    async Task Because() => _result = await _notifier.Notify(_httpContext, _principal, "workforce");

    [Fact] void should_notify() => _result.ShouldEqual(SignInNotificationResult.Notified);
    [Fact] void should_post_the_canonical_subject() => _handler.LastRequestBody!.ShouldContain("\"subject\":\"configured-subject\"");
    [Fact] void should_post_the_provider_key() => _handler.LastRequestBody!.ShouldContain("\"providerKey\":\"workforce\"");
}

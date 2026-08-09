// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.SignIns.for_SignInNotifier.given;

public class a_canonical_sign_in_notifier : a_sign_in_notifier
{
    protected override SignInNotifier CreateNotifier(
        C.AuthProxy configuration,
        IOptionsMonitor<C.AuthProxy> optionsMonitor,
        IHttpClientFactory httpClientFactory)
    {
        var authenticationOptions = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationOptions.CurrentValue.Returns(configuration.Authentication);
        return new(
            optionsMonitor,
            new ClientLocationResolver(),
            httpClientFactory,
            Substitute.For<ILogger<SignInNotifier>>(),
            new CanonicalIdentityResolver(authenticationOptions));
    }
}

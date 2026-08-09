// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.given;

public class a_canonical_invite_exchange : an_invite_exchange
{
    protected override InviteMiddleware CreateMiddleware(
        C.AuthProxy configuration,
        IOptionsMonitor<C.AuthProxy> optionsMonitor,
        IHttpClientFactory httpClientFactory)
    {
        var authenticationOptions = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationOptions.CurrentValue.Returns(configuration.Authentication);
        return new(
            _ =>
            {
                _nextCalled = true;
                return Task.CompletedTask;
            },
            new InviteTokenValidator(optionsMonitor),
            optionsMonitor,
            authenticationOptions,
            Substitute.For<ITenantResolver>(),
            httpClientFactory,
            _errorPageProvider,
            Substitute.For<ILogger<InviteMiddleware>>(),
            new CanonicalIdentityResolver(authenticationOptions));
    }
}

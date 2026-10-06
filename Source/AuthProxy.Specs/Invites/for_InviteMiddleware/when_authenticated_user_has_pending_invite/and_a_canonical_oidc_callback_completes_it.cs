// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Invites.for_InviteMiddleware.when_authenticated_user_has_pending_invite;

public class and_a_canonical_oidc_callback_completes_it : given.a_canonical_invite_exchange
{
    InviteCompletion _completion;
    InviteExchangeResult _result;

    protected override void ConfigureAuthentication(C.AuthProxy configuration) => configuration.Authentication = CanonicalOidcFixture.Configuration();

    protected override InviteMiddleware CreateMiddleware(C.AuthProxy configuration, IOptionsMonitor<C.AuthProxy> optionsMonitor, IHttpClientFactory httpClientFactory)
    {
        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(configuration.Authentication);
        _completion = new(new InviteTokenValidator(optionsMonitor), optionsMonitor, authentication, Substitute.For<ITenantResolver>(), httpClientFactory, Substitute.For<ILogger<InviteMiddleware>>(), CanonicalOidcFixture.Resolver(configuration.Authentication), null, null);
        return base.CreateMiddleware(configuration, optionsMonitor, httpClientFactory);
    }

    async Task Because()
    {
        var properties = new AuthenticationProperties();
        properties.Items[Authentication.AuthenticationServiceCollectionExtensions.AuthenticationSchemeStateKey] = "workforce";
        _result = await _completion.ExchangeForTicket(_context, CreateSignedToken(), CanonicalOidcFixture.Principal(), properties);
    }

    [Fact] void should_exchange_the_invitation() => _result.ShouldEqual(InviteExchangeResult.Success);
    [Fact] void should_post_the_canonical_subject() => _exchangeRequestBody.ShouldContain("\"subject\":\"configured-subject\"");
    [Fact] void should_post_the_provider_key() => _exchangeRequestBody.ShouldContain("\"providerKey\":\"workforce\"");
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails;

public class when_a_valid_invitation_offers_provider_selection : given.an_email_bound_invitation
{
    protected override void ConfigureAuthentication(C.AuthProxy configuration) => configuration.Authentication.OAuthProviders = [new() { Name = "First" }, new() { Name = "Second" }];

    protected override InviteMiddleware CreateMiddleware(C.AuthProxy configuration, IOptionsMonitor<C.AuthProxy> optionsMonitor, IHttpClientFactory httpClientFactory)
    {
        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(configuration.Authentication);
        return new(_ => Task.CompletedTask, new InviteTokenValidator(optionsMonitor), optionsMonitor, authentication, Substitute.For<ITenantResolver>(), httpClientFactory, _errorPageProvider, Substitute.For<ILogger<InviteMiddleware>>());
    }

    void Establish()
    {
        _invited = "<b>invite</b>@example.com";
        _context.Request.Path = $"/invite/{CreateSignedToken(claims: [new Claim(InviteEmailClaim, _invited)])}";
    }

    Task Because() => _middleware.InvokeAsync(_context);

    [Fact] void should_offer_provider_selection() => _page.ShouldEqual(WellKnownPageNames.InvitationSelectProvider);
    [Fact] void should_encode_the_invited_address() => _substitutions!["{{invitedEmail}}"].ShouldEqual("&lt;b&gt;invite&lt;/b&gt;@example.com");
    [Fact] void should_supply_no_asserted_address_before_authentication() => _substitutions!["{{assertedEmail}}"].ShouldBeEmpty();
}

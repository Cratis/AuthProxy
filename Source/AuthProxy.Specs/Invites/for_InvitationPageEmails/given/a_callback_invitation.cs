// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Invites.for_InvitationPageEmails.given;

public class a_callback_invitation : an_email_bound_invitation
{
    private protected InviteCallbackCompletionResult _result;
    InviteCompletion _completion;
    IInviteTokenValidator _validator;
    ServiceProvider? _services;
    TicketReceivedContext _ticket;

    protected override InviteMiddleware CreateMiddleware(C.AuthProxy configuration, IOptionsMonitor<C.AuthProxy> optionsMonitor, IHttpClientFactory httpClientFactory)
    {
        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(configuration.Authentication);
        _validator = new InviteTokenValidator(optionsMonitor);
        _completion = new(_validator, optionsMonitor, authentication, Substitute.For<ITenantResolver>(), httpClientFactory, Substitute.For<ILogger<InviteMiddleware>>(), null, null, null);
        return base.CreateMiddleware(configuration, optionsMonitor, httpClientFactory);
    }

    protected void GivenACallback(bool correlated = true, bool validCapability = true, bool authenticated = true)
    {
        var signingKey = validCapability ? _signingKey : TokenFixture.GenerateKeyPair().PrivateKey;
        var token = CreateSignedToken(signingKey: signingKey, claims: [new Claim(InviteEmailClaim, _invited)]);
        _context.Request.Headers.Cookie = $"{Cookies.InviteToken}={token}";
        var properties = new AuthenticationProperties();
        InvitationAuthenticationState.BindCapability(properties, correlated ? token : "another-capability");
        var principal = new ClaimsPrincipal(new ClaimsIdentity(ProviderClaims.Prepend(new Claim("sub", "subject")), "workforce"));
        _services = new ServiceCollection()
            .AddLogging()
            .AddSingleton<IInviteCompletion>(_completion)
            .AddSingleton(_validator)
            .AddSingleton(_errorPageProvider)
            .AddSingleton(Substitute.For<IAuthenticationService>())
            .BuildServiceProvider();
        _context.RequestServices = _services;
        _ticket = new(_context, new("workforce", null, typeof(OAuthHandler<OAuthOptions>)), new OAuthOptions { SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme }, new(principal, properties, "workforce"));
        if (!authenticated)
        {
            _ticket.Principal = null;
        }
    }

    protected async Task CompleteCallback() => _result = await InviteCallbackCompletion.TryComplete(_ticket);

    async Task Destroy()
    {
        if (_services is not null)
        {
            await _services.DisposeAsync();
        }
    }
}

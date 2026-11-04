// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions.given;
using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_AuthenticationServiceCollectionExtensions;

/// <summary>
/// Specifies that the provider callback hands the freshly authenticated user to the sign-in callbacks once, right
/// after the sign-in succeeds, together with the scheme that established it.
/// </summary>
public class when_a_sign_in_completes_and_services_have_callbacks : configured_canonical_provider_callbacks
{
    TicketReceivedContext _ticketContext;
    AuthenticationProperties _properties;

    async Task Because()
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("id", "github-subject")], "github"));
        _properties = new AuthenticationProperties();
        _ticketContext = TicketContext(Context(), "github", _oauthOptions, principal, _properties);
        await _oauthOptions.Events.OnTicketReceived(_ticketContext);
    }

    [Fact] void should_report_the_sign_in_once() =>
        _callbackDispatcher.Received(1).SignedIn(_ticketContext.HttpContext, _ticketContext.Principal!, "github", _properties);
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_ClientPrincipalExtensions.given;

public class a_recorded_session : Specification
{
    protected DefaultHttpContext _context;
    protected AuthenticationProperties _properties;
    protected ClientPrincipal _principal;

    void Establish()
    {
        var user = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "user-42")], "AuthenticationTypes.Federation"));
        _properties = new AuthenticationProperties();
        SessionProvider.Stamp(user, _properties, "microsoft");
        SessionStart.Stamp(_properties, DateTimeOffset.FromUnixTimeSeconds(1700000000));
        _context = new DefaultHttpContext { RequestServices = new ServiceCollection().BuildServiceProvider(), User = user };
        _context.Features.Set<IAuthenticateResultFeature>(new ResultFeature(AuthenticateResult.Success(new AuthenticationTicket(user, _properties, CookieAuthenticationDefaults.AuthenticationScheme))));
        _principal = _context.BuildClientPrincipal()!;
    }

    protected sealed class ResultFeature(AuthenticateResult result) : IAuthenticateResultFeature
    {
        public AuthenticateResult? AuthenticateResult { get; set; } = result;
    }
}

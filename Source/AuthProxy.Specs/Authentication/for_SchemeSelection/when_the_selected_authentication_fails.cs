// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Authentication.for_SchemeSelection;

public class when_the_selected_authentication_fails : Specification
{
    DefaultHttpContext _context;
    bool _continued;

    async Task Because()
    {
        var authentication = Substitute.For<IAuthenticationService>();
        _context = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("sub", "prior-user")], "prior-scheme")),
        };
        authentication.AuthenticateAsync(_context, null).Returns(AuthenticateResult.Fail("Authentication did not succeed."));
        await using var services = new ServiceCollection().AddSingleton(authentication).BuildServiceProvider();
        _context.RequestServices = services;
        _context.Request.Headers.Authorization = "Bearer invalid-spec-token";
        var middleware = new RequestAuthenticationMiddleware(_ =>
        {
            _continued = true;
            return Task.CompletedTask;
        });
        await middleware.InvokeAsync(_context);
    }

    [Fact] void should_return_unauthorized() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status401Unauthorized);
    [Fact] void should_not_continue_with_an_existing_identity() => _continued.ShouldBeFalse();
}

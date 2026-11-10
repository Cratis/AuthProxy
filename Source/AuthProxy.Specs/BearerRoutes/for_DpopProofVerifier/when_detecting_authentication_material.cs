// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.BearerRoutes.for_DpopProofVerifier;

public class when_detecting_authentication_material : given_a_dpop_gate
{
    [Theory]
    [InlineData("DPoP token", true)]
    [InlineData("dpop\ttoken", true)]
    [InlineData("Bearer token", true)]
    [InlineData("bearer\ttoken", true)]
    [InlineData("Basic token", false)]
    [InlineData("", false)]
    public void should_detect_dpop_without_changing_other_schemes(string authorization, bool expected)
    {
        var request = new DefaultHttpContext().Request;
        request.Headers.Authorization = authorization;
        RequestAuthentication.HasBearer(request).ShouldEqual(expected);
    }

    [Theory]
    [InlineData("DPoP")]
    [InlineData("Bearer")]
    public async Task should_refuse_cookie_mixing_for_both_token_schemes(string scheme)
    {
        var monitor = Substitute.For<IOptionsMonitor<CookieAuthenticationOptions>>();
        monitor.Get(Arg.Any<string>()).Returns(new CookieAuthenticationOptions { Cookie = new CookieBuilder { Name = "synthetic-session" } });
        await using var services = new ServiceCollection().AddSingleton(monitor).BuildServiceProvider();
        var context = Request(scheme: scheme);
        context.RequestServices = services;
        context.Request.Headers.Cookie = "synthetic-session=synthetic-value";
        RequestAuthentication.IsAmbiguous(context).ShouldBeTrue();
        await Gate.InvokeAsync(context);
        Refused(context, 400, null);
    }

    [Fact]
    public void should_not_treat_a_proof_header_alone_as_a_bearer_scheme()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["DPoP"] = "synthetic-proof";
        RequestAuthentication.HasBearer(context.Request).ShouldBeFalse();
        RequestAuthentication.IsAmbiguous(context).ShouldBeFalse();
    }

    [Fact]
    public async Task should_refuse_dpop_outside_an_opted_in_route()
    {
        Policy.Dpop = null;
        var context = Request();
        await Gate.InvokeAsync(context);
        Refused(context, 401, "invalid_token");
    }
}

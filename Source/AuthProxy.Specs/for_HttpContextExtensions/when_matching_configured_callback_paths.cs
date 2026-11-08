// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_HttpContextExtensions;

public class when_matching_configured_callback_paths : Specification
{
    ServiceProvider _services;

    void Establish()
    {
        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders = [new() { Name = "Provider One" }],
            OAuthProviders = [new() { Name = "GitHub" }]
        });
        _services = new ServiceCollection()
            .AddSingleton(authentication)
            .Configure<OAuthOptions>("github", options => options.CallbackPath = "/signin-github")
            .Configure<OpenIdConnectOptions>("provider-one", options => options.CallbackPath = "/custom-callback")
            .BuildServiceProvider();
    }

    void Destroy() => _services.Dispose();

    [Theory]
    [InlineData("/signin-github", true)]
    [InlineData("/SIGNIN-GITHUB", true)]
    [InlineData("/custom-callback", true)]
    [InlineData("/signin-x", false)]
    [InlineData("/signin-github/private", false)]
    [InlineData("/signin-github-other", false)]
    [InlineData("/signin-provider-one", false)]
    [InlineData("/custom-callback/private", false)]
    public void should_exempt_only_the_effective_callback_path(string path, bool expected)
    {
        var context = new DefaultHttpContext { RequestServices = _services };
        context.Request.Path = path;
        context.IsAuthenticationBootstrap().ShouldEqual(expected);
    }
}

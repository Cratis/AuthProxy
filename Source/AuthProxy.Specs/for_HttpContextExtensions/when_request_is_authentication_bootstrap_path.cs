// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_HttpContextExtensions;

public class when_request_is_authentication_bootstrap_path : Specification
{
    DefaultHttpContext _context;
    bool _isAuthenticationBootstrap;

    void Establish()
    {
        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(new C.Authentication { OAuthProviders = [new() { Name = "GitHub" }] });
        _context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddSingleton(authentication).BuildServiceProvider()
        };
        _context.Request.Path = "/signin-github";
    }

    void Destroy() => (_context.RequestServices as IDisposable)?.Dispose();

    void Because() => _isAuthenticationBootstrap = _context.IsAuthenticationBootstrap();

    [Fact] void should_identify_the_request_as_authentication_bootstrap() => _isAuthenticationBootstrap.ShouldBeTrue();
}
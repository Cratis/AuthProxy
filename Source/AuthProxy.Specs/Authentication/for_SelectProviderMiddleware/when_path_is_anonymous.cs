// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SelectProviderMiddleware;

/// <summary>
/// An unauthenticated request to a declared anonymous path must be forwarded, while a sibling path that
/// was not declared must still be answered with the provider-selection page.
/// <para>
/// Both facts are asserted from the same setup so that the skip cannot be mistaken for a middleware that
/// simply forwards everything. The undeclared path is requested as a browser navigation, which is the only
/// caller still answered with the page — see
/// <see cref="when_the_caller_is_not_navigating.and_multiple_providers_are_configured"/> for the rest.
/// </para>
/// </summary>
public class when_path_is_anonymous : Specification
{
    const string AnonymousPath = "/portal";

    SelectProviderMiddleware _middleware;
    DefaultHttpContext _anonymousContext;
    DefaultHttpContext _undeclaredContext;
    IErrorPageProvider _errorPageProvider;
    bool _nextCalledForAnonymousPath;
    bool _nextCalledForUndeclaredPath;

    void Establish()
    {
        var proxyConfig = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        proxyConfig.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["test"] = new() { AnonymousPaths = [AnonymousPath] }
            }
        });

        var authConfig = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authConfig.CurrentValue.Returns(new C.Authentication
        {
            OidcProviders =
            [
                new C.OidcProvider { Name = "p1", Authority = "https://a.example.com", ClientId = "c1" },
                new C.OidcProvider { Name = "p2", Authority = "https://b.example.com", ClientId = "c2" }
            ]
        });

        _errorPageProvider = Substitute.For<IErrorPageProvider>();

        _anonymousContext = new DefaultHttpContext();
        _anonymousContext.Request.Path = $"{AnonymousPath}/some-token";

        _undeclaredContext = new DefaultHttpContext();
        _undeclaredContext.Request.Path = "/portalx";

        // Navigated to in a browser, so the undeclared path is answered with the page rather than the
        // status a non-navigating caller gets — which keeps this spec about the path list alone.
        _undeclaredContext.Request.Headers["Sec-Fetch-Dest"] = "document";

        _middleware = new SelectProviderMiddleware(
            context =>
            {
                if (context == _anonymousContext)
                {
                    _nextCalledForAnonymousPath = true;
                }
                else
                {
                    _nextCalledForUndeclaredPath = true;
                }

                return Task.CompletedTask;
            },
            proxyConfig,
            authConfig,
            _errorPageProvider,
            Substitute.For<ITenantResolver>(),
            Substitute.For<IAuthenticationSchemeProvider>());
    }

    async Task Because()
    {
        await _middleware.InvokeAsync(_anonymousContext);
        await _middleware.InvokeAsync(_undeclaredContext);
    }

    [Fact] void should_forward_the_declared_path() => _nextCalledForAnonymousPath.ShouldBeTrue();
    [Fact] void should_not_forward_a_path_sharing_only_a_string_prefix() => _nextCalledForUndeclaredPath.ShouldBeFalse();

    [Fact] void should_not_serve_the_selection_page_for_the_declared_path() => _errorPageProvider.DidNotReceive().WriteErrorPageAsync(_anonymousContext, Arg.Any<string>(), Arg.Any<int>());
    [Fact] void should_serve_the_selection_page_for_a_path_sharing_only_a_string_prefix() => _errorPageProvider.Received(1).WriteErrorPageAsync(_undeclaredContext, WellKnownPageNames.SelectProvider, StatusCodes.Status200OK);
}

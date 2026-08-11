// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.Links;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Authentication.for_RemoteAuthenticationFailureHandler;

/// <summary>
/// A failed link challenge must not fall back to the sign-in machinery: the person still holds their
/// primary session, and the provider-selection page answers with full sign-ins — offering to replace the
/// very session the link was preserving, and looping straight back into whatever failed (#104). The link
/// flow ends on its own failure page instead.
/// </summary>
public class when_a_link_challenge_fails : given.a_remote_authentication_failure_context
{
    RemoteFailureContext _failureContext;

    void Establish()
    {
        _context.Request.Headers.Cookie = $"{Cookies.CorrelationPrefix}abc=one; {Cookies.NoncePrefix}def=two";
        _context.RequestServices = ServicesWithErrorPages();

        var properties = new AuthenticationProperties { RedirectUri = "/settings/credentials" };
        properties.Items[LinkMiddleware.LinkModePropertyKey] = "true";
        properties.Items[LinkMiddleware.LinkTokenPropertyKey] = "the-one-time-link-token";

        _failureContext = new RemoteFailureContext(_context, _scheme, _options, new InvalidOperationException("Correlation failed."))
        {
            Properties = properties
        };
    }

    async Task Because() => await RemoteAuthenticationFailureHandler.HandleRemoteFailure(_failureContext);

    [Fact] void should_handle_the_response() => _failureContext.Result.Handled.ShouldBeTrue();
    [Fact] void should_answer_with_a_non_success_status() => _context.Response.StatusCode.ShouldEqual(StatusCodes.Status403Forbidden);
    [Fact] void should_not_redirect() => _context.Response.Headers.Location.ToString().ShouldBeEmpty();

    [Fact] void should_not_fall_back_to_provider_selection() =>
        _context.Response.Headers.Location.ToString().ShouldNotContain(WellKnownPaths.LoginPage);

    [Fact] void should_write_the_link_failure_page() =>
        Encoding.UTF8.GetString(((MemoryStream)_context.Response.Body).ToArray()).ShouldContain("Link Not Completed");

    [Fact] void should_clear_the_correlation_cookie() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.CorrelationPrefix}abc=; expires");

    [Fact] void should_clear_the_nonce_cookie() =>
        _context.Response.Headers.SetCookie.ToString().ShouldContain($"{Cookies.NoncePrefix}def=; expires");

    [Fact] void should_forbid_framing_by_default() =>
        _context.Response.Headers.ContentSecurityPolicy.ToString().ShouldEqual("frame-ancestors 'none'");

    IServiceProvider ServicesWithErrorPages()
    {
        var loggerFactory = Substitute.For<ILoggerFactory>();
        loggerFactory.CreateLogger(Arg.Any<string>()).Returns(Substitute.For<ILogger>());

        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns(AppContext.BaseDirectory);

        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(ILoggerFactory)).Returns(loggerFactory);
        serviceProvider.GetService(typeof(IErrorPageProvider)).Returns(new ErrorPageProvider(environment, config));
        serviceProvider.GetService(typeof(IOptionsMonitor<C.AuthProxy>)).Returns(config);
        return serviceProvider;
    }
}

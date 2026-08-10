// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.given;

public class a_link_callback_context : Specification
{
    protected const string ReturnUrl = "/settings/credentials";
    protected const string LinkToken = "the-one-time-link-token";
    protected const string ProviderSubject = "linked-subject-123";

    protected DefaultHttpContext _context;
    protected TicketReceivedContext _ticketContext;
    protected AuthenticationProperties _properties;
    protected ILinkSubjectExchanger _exchanger;
    protected ISignInNotifier _signInNotifier;

    protected virtual LinkExchangeResult ExchangeResult => LinkExchangeResult.Success;

    protected virtual string? RecordedReturnUrl => ReturnUrl;

    protected string ResponseBody() => Encoding.UTF8.GetString(((MemoryStream)_context.Response.Body).ToArray());

    void Establish()
    {
        _context = new DefaultHttpContext();
        _context.Request.Scheme = "https";
        _context.Request.Host = new HostString("cratis.studio");
        _context.Request.Path = "/signin-github";
        _context.Response.Body = new MemoryStream();

        _exchanger = Substitute.For<ILinkSubjectExchanger>();
        _exchanger
            .Exchange(Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
            .Returns(ExchangeResult);
        _signInNotifier = Substitute.For<ISignInNotifier>();

        var loggerFactory = Substitute.For<ILoggerFactory>();
        loggerFactory.CreateLogger(Arg.Any<string>()).Returns(Substitute.For<ILogger>());

        // The error page provider is built before the service provider is configured: it substitutes and
        // configures collaborators of its own, and doing that inside a Returns(...) argument would clobber
        // the call NSubstitute is waiting to configure.
        var errorPageProvider = CreateErrorPageProvider();

        var serviceProvider = Substitute.For<IServiceProvider>();
        serviceProvider.GetService(typeof(ILoggerFactory)).Returns(loggerFactory);
        serviceProvider.GetService(typeof(ILinkSubjectExchanger)).Returns(_exchanger);
        serviceProvider.GetService(typeof(IErrorPageProvider)).Returns(errorPageProvider);
        serviceProvider.GetService(typeof(ISignInNotifier)).Returns(_signInNotifier);
        _context.RequestServices = serviceProvider;

        _properties = new AuthenticationProperties { RedirectUri = RecordedReturnUrl };
        _properties.Items[LinkMiddleware.LinkModePropertyKey] = "true";
        _properties.Items[LinkMiddleware.LinkTokenPropertyKey] = LinkToken;

        var scheme = new AuthenticationScheme("github", "github", typeof(OpenIdConnectHandler));
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim("sub", ProviderSubject)
        ],
        "github"));

        _ticketContext = new TicketReceivedContext(
            _context,
            scheme,
            new RemoteAuthenticationOptions(),
            new AuthenticationTicket(principal, _properties, scheme.Name));
    }

    static IErrorPageProvider CreateErrorPageProvider()
    {
        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns(AppContext.BaseDirectory);
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy());
        return new ErrorPageProvider(environment, config);
    }
}

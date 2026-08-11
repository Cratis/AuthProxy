// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;

namespace Cratis.AuthProxy.Links.for_LinkCallbackCompletion.when_the_exchange_fails;

/// <summary>
/// The exchange fails for six distinct causes, and the browser must not be able to tell them apart. Driving
/// the real <see cref="LinkSubjectExchanger"/> through every one of them and comparing the complete answers —
/// status, every response header, the body, and whether the response was handled — is what makes that a
/// property of the system rather than of one spec's mock.
/// </summary>
/// <remarks>
/// "The provider identity is unknown", "the account does not exist" and "the endpoint was unreachable" are
/// exactly the distinctions an attacker enumerates, and the person in front of the browser can act on none
/// of them: the recovery is the same in every case.
/// </remarks>
public class and_the_failure_mode_varies : Specification
{
    const string ExchangeUrl = "https://studio.example.com/api/internal/identity-providers/link";
    const string LinkToken = "the-one-time-link-token";
    const string ReturnUrl = "/settings/credentials";
    const string ProviderSubject = "linked-subject-123";

    readonly List<string> _answers = [];

    async Task Because()
    {
        // The exchange URL is not configured — the application is never contacted.
        _answers.Add(await Answer(new C.AuthProxy(), WithSubject(), WithToken(), Responds(HttpStatusCode.OK)));

        // The one-time link token never made it through the challenge properties.
        _answers.Add(await Answer(Configured(), WithSubject(), WithoutToken(), Responds(HttpStatusCode.OK)));

        // A canonical provider whose configured subject claim the principal does not carry.
        _answers.Add(await Answer(Canonical(), WithSubject(), WithToken(), Responds(HttpStatusCode.OK)));

        // No subject can be resolved from the principal at all.
        _answers.Add(await Answer(Configured(), WithoutSubject(), WithToken(), Responds(HttpStatusCode.OK)));

        // The call leaves the process and never arrives — DNS, TLS, or a timeout.
        _answers.Add(await Answer(Configured(), WithSubject(), WithToken(), new ThrowingHttpMessageHandler()));

        // The application was reached and refused.
        _answers.Add(await Answer(Configured(), WithSubject(), WithToken(), Responds(HttpStatusCode.InternalServerError)));
    }

    [Fact] void should_answer_every_failure_mode() => _answers.Count.ShouldEqual(6);
    [Fact] void should_answer_every_failure_mode_identically() => _answers.Distinct(StringComparer.Ordinal).Count().ShouldEqual(1);
    [Fact] void should_answer_every_failure_mode_with_a_non_success_status() =>
        _answers.Where(_ => !_.StartsWith($"{StatusCodes.Status403Forbidden}|", StringComparison.Ordinal)).ShouldBeEmpty();
    [Fact] void should_never_redirect_to_the_return_url() =>
        _answers.Where(_ => _.Contains(ReturnUrl, StringComparison.Ordinal)).ShouldBeEmpty();
    [Fact] void should_never_disclose_the_exchange_url() =>
        _answers.Where(_ => _.Contains(ExchangeUrl, StringComparison.Ordinal)).ShouldBeEmpty();
    [Fact] void should_never_disclose_the_provider_subject() =>
        _answers.Where(_ => _.Contains(ProviderSubject, StringComparison.Ordinal)).ShouldBeEmpty();
    [Fact] void should_never_disclose_the_link_token() =>
        _answers.Where(_ => _.Contains(LinkToken, StringComparison.Ordinal)).ShouldBeEmpty();

    static C.AuthProxy Configured() => new() { Link = new C.Link { ExchangeUrl = ExchangeUrl } };

    static C.AuthProxy Canonical() => new()
    {
        Link = new C.Link { ExchangeUrl = ExchangeUrl },
        Authentication = new C.Authentication
        {
            OAuthProviders =
            [
                new C.OAuthProvider
                {
                    Name = "GitHub",
                    CanonicalIdentity = new C.CanonicalIdentity
                    {
                        ProviderKey = "workforce",
                        SubjectClaimType = "oid",
                        Issuer = "https://identity.example.com"
                    }
                }
            ]
        }
    };

    static ClaimsPrincipal WithSubject() => new(new ClaimsIdentity(
    [
        new Claim("sub", ProviderSubject),
        new Claim("iss", "https://github.com")
    ],
    "github"));

    static ClaimsPrincipal WithoutSubject() => new(new ClaimsIdentity(
    [
        new Claim("email", "person@example.com")
    ],
    "github"));

    static AuthenticationProperties WithToken()
    {
        var properties = WithoutToken();
        properties.Items[LinkMiddleware.LinkTokenPropertyKey] = LinkToken;
        return properties;
    }

    static AuthenticationProperties WithoutToken()
    {
        var properties = new AuthenticationProperties { RedirectUri = ReturnUrl };
        properties.Items[LinkMiddleware.LinkModePropertyKey] = "true";
        return properties;
    }

    static RecordingHttpMessageHandler Responds(HttpStatusCode statusCode) => new(statusCode);

    static async Task<string> Answer(
        C.AuthProxy configuration,
        ClaimsPrincipal principal,
        AuthenticationProperties properties,
        HttpMessageHandler messageHandler)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("cratis.studio");
        context.Request.Path = "/signin-github";
        context.Response.Body = new MemoryStream();
        context.RequestServices = CreateServices(configuration, messageHandler);

        var scheme = new AuthenticationScheme("github", "github", typeof(OpenIdConnectHandler));
        var ticketContext = new TicketReceivedContext(
            context,
            scheme,
            new RemoteAuthenticationOptions(),
            new AuthenticationTicket(principal, properties, scheme.Name));

        await LinkCallbackCompletion.Complete(ticketContext, properties);

        var headers = string.Join(
            ';',
            context.Response.Headers
                .OrderBy(_ => _.Key, StringComparer.Ordinal)
                .Select(_ => $"{_.Key}={_.Value}"));
        var body = Encoding.UTF8.GetString(((MemoryStream)context.Response.Body).ToArray());

        return $"{context.Response.StatusCode}|{headers}|{body}|{ticketContext.Result.Handled}";
    }

    static IServiceProvider CreateServices(C.AuthProxy configuration, HttpMessageHandler messageHandler)
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(configuration);

        var authentication = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authentication.CurrentValue.Returns(configuration.Authentication);

        var httpClientFactory = Substitute.For<IHttpClientFactory>();
        httpClientFactory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(messageHandler));

        var loggerFactory = Substitute.For<ILoggerFactory>();
        loggerFactory.CreateLogger(Arg.Any<string>()).Returns(Substitute.For<ILogger>());

        var environment = Substitute.For<IWebHostEnvironment>();
        environment.ContentRootPath.Returns(AppContext.BaseDirectory);

        var errorPageProvider = new ErrorPageProvider(environment, config);
        var exchanger = new LinkSubjectExchanger(
            config,
            httpClientFactory,
            Substitute.For<ILogger<LinkSubjectExchanger>>(),
            new CanonicalIdentityResolver(authentication));

        var services = Substitute.For<IServiceProvider>();
        services.GetService(typeof(ILoggerFactory)).Returns(loggerFactory);
        services.GetService(typeof(IErrorPageProvider)).Returns(errorPageProvider);
        services.GetService(typeof(ILinkSubjectExchanger)).Returns(exchanger);

        return services;
    }
}

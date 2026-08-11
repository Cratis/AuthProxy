// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Cratis.AuthProxy.Security.given;

/// <summary>
/// A running AuthProxy that has declared where its ingress is, in front of a real recording origin.
/// </summary>
/// <remarks>
/// A second harness rather than a setting on the shared one, for the same reason the claim-gated deployment
/// is its own: the shared harness is the deployment every other security spec reasons about, and it has
/// declared no boundary — which is the compatibility fallback, and a premise worth keeping intact.
/// <para>
/// Two hops are declared rather than one, because a boundary that were bound but never read would look
/// identical to a correct one at a single hop: with the framework's default of one, a chain of two would
/// still yield a plausible-looking answer. Requiring the second hop to be honored means the configured value
/// has to have reached the middleware.
/// </para>
/// <para>
/// Two identity providers are configured so an unauthenticated browser is served the selection page rather
/// than challenged. That page sets a cookie whose <c>Secure</c> flag is taken straight from the request
/// scheme, which is what makes a spoofed <c>X-Forwarded-Proto</c> observable as something a browser would act
/// on rather than as an internal value.
/// </para>
/// </remarks>
public class TrustedProxyHarness : WebApplicationFactory<Program>
{
    /// <summary>The header a spec sends to choose the address the connection appears to come from.</summary>
    public const string PeerHeader = "X-Security-Spec-Peer";

    /// <summary>The header a spec sends to have a sign-in notification raised for the request.</summary>
    public const string NotifySignInHeader = "X-Security-Spec-Notify-Sign-In";

    /// <summary>The range this deployment declares as its own ingress.</summary>
    public const string TrustedRange = "203.0.113.0/24";

    /// <summary>The ingress address requests legitimately arrive from.</summary>
    public const string TrustedPeer = "203.0.113.10";

    /// <summary>A second address inside the declared range, standing in for an inner hop.</summary>
    public const string SecondTrustedPeer = "203.0.113.20";

    /// <summary>A third address inside the declared range, standing in for a further inner hop.</summary>
    public const string ThirdTrustedPeer = "203.0.113.30";

    /// <summary>An address outside the declared range — anyone who can reach the proxy directly.</summary>
    public const string UntrustedPeer = "198.51.100.10";

    /// <summary>How many trusted proxies this deployment declares a request passes through.</summary>
    public const int ForwardLimit = 2;

    /// <summary>The tenant every request resolves to.</summary>
    public const string TenantId = "33333333-3333-3333-3333-333333333333";

    /// <summary>The one path this deployment declares anonymous.</summary>
    public const string AnonymousPath = "/public";

    /// <summary>A path that is not anonymous and therefore requires a session.</summary>
    public const string ProtectedPath = "/private";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    /// <summary>
    /// Initializes a new instance of the <see cref="TrustedProxyHarness"/> class.
    /// </summary>
    public TrustedProxyHarness()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, WellKnownPageNames.SelectProvider), "<html><body>Select Provider</body></html>");

        Origin = RecordingBackend.Start().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Gets the origin AuthProxy forwards to, and the record of what reached it.
    /// </summary>
    public RecordingBackend Origin { get; }

    /// <summary>
    /// Gets what the proxy normalized the most recent request to.
    /// </summary>
    public RequestObservations Observations { get; } = new();

    /// <summary>
    /// Gets everything the proxy warned about, including at startup.
    /// </summary>
    public CapturedLogs Logs { get; } = new();

    /// <summary>
    /// Builds a request that appears to have been accepted from a chosen peer.
    /// </summary>
    /// <param name="peer">The address the connection appears to come from.</param>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage From(string peer, string pathAndQuery)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, pathAndQuery);
        request.Headers.TryAddWithoutValidation(PeerHeader, peer);

        return request;
    }

    /// <summary>
    /// Builds a request that appears to have been accepted from a chosen peer and that raises a sign-in
    /// notification once the proxy is done with it.
    /// </summary>
    /// <param name="peer">The address the connection appears to come from.</param>
    /// <param name="pathAndQuery">The path and query to request.</param>
    /// <returns>The request.</returns>
    public static HttpRequestMessage SigningInFrom(string peer, string pathAndQuery)
    {
        var request = From(peer, pathAndQuery);
        request.Headers.TryAddWithoutValidation(NotifySignInHeader, "true");

        return request;
    }

    /// <summary>
    /// Creates a client that surfaces redirects as responses rather than following them.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateSecurityClient() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);

        if (!disposing)
        {
            return;
        }

        Origin.DisposeAsync().AsTask().GetAwaiter().GetResult();

        if (Directory.Exists(_pagesPath))
        {
            Directory.Delete(_pagesPath, recursive: true);
        }
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder
            .UseEnvironment("Production")
            .ConfigureLogging(logging => logging.AddProvider(Logs))
            .ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{C.AuthProxy.SectionKey}:Services:app:Backend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:Frontend:BaseUrl"] = Origin.BaseUrl,
                [$"{C.AuthProxy.SectionKey}:Services:app:AnonymousPaths:0"] = AnonymousPath,

                [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,

                [$"{C.Ingress.SectionKey}:TrustedProxies:0"] = TrustedRange,
                [$"{C.Ingress.SectionKey}:ForwardLimit"] = ForwardLimit.ToString(CultureInfo.InvariantCulture),

                [$"{C.AuthProxy.SectionKey}:SignIn:NotifyUrl"] = Origin.SignInNotificationUrl,

                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
                [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,

                [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = "Provider One",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = "https://login.example.test/one",
                [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "client-one",

                [$"{C.Authentication.SectionKey}:OidcProviders:1:Name"] = "Provider Two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:Authority"] = "https://login.example.test/two",
                [$"{C.Authentication.SectionKey}:OidcProviders:1:ClientId"] = "client-two",
            }))
            .ConfigureTestServices(services =>
            {
                services.AddSingleton<IStartupFilter>(new SimulatedPeerStartupFilter(Observations, UntrustedPeer));
                services
                    .AddAuthentication(HeaderAuthenticationHandler.Scheme)
                    .AddScheme<AuthenticationSchemeOptions, HeaderAuthenticationHandler>(
                        HeaderAuthenticationHandler.Scheme,
                        _ => { });
            });
    }
}

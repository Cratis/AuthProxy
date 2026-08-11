// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// WebApplicationFactory that keeps AuthProxy's real authentication stack — the cookie scheme and one
/// configured OAuth provider — and fakes only what lives outside the proxy: the identity provider's token
/// and user-information endpoints, the invitation exchange endpoint, and the identity backend.
/// </summary>
/// <remarks>
/// The provider handshake is driven for real: the invitation challenge protects its state (including the
/// invitation capability binding) with the same machinery production uses, and the callback unprotects it
/// the same way. Nothing fabricates the binding — a session only carries it because the challenge that
/// established the session bound it, which is exactly the evidence the callback completion trusts.
/// </remarks>
public class CallbackAuthProxyFactory : WebApplicationFactory<Program>
{
    public const string ProviderName = "TestIdp";
    public const string ProviderScheme = "testidp";
    public const string ExchangeUrl = "http://exchange.test/invites/exchange";
    public const string IdentityBackendBaseUrl = "http://identity.test/";
    public const string LobbyUrl = "http://lobby.test/";
    public const string SubjectAlreadyExistsUrl = "http://lobby.test/already-a-member";
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    public const string TenantClaim = "tenant_id";
    public const string SessionCookieName = ".Cratis.AuthProxy.Auth.v2";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());

    int _exchangeCallCount;

    /// <summary>Initializes a new instance of the <see cref="CallbackAuthProxyFactory"/> class.</summary>
    public CallbackAuthProxyFactory()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-expired.html"), "<html><body><h1>Invitation Expired</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-invalid.html"), "<html><body><h1>Invitation Invalid</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-select-provider.html"), "<html><body><h1>Select Provider</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-subject-already-exists.html"), "<html><body><h1>Already A Member</h1></body></html>");
    }

    public (RsaSecurityKey PrivateKey, string PublicKeyPem) InviteKeyPair { get; } = TokenFixture.GenerateKeyPair();

    public int ExchangeCallCount => _exchangeCallCount;

    /// <summary>Gets or sets the status the faked invitation exchange endpoint answers with.</summary>
    public HttpStatusCode ExchangeStatusCode { get; set; } = HttpStatusCode.OK;

    /// <summary>
    /// Extracts the reusable <c>name=value</c> cookie pairs a response set, skipping deletions.
    /// </summary>
    /// <param name="response">The response whose cookies to collect.</param>
    /// <returns>The cookie pairs, ready for a <c>Cookie</c> request header.</returns>
    public static IReadOnlyList<string> CookiesFrom(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var setCookies)
            ? setCookies
                .Select(setCookie => setCookie.Split(';')[0])
                .Where(pair => pair.Split('=', 2) is [_, { Length: > 0 }])
                .ToArray()
            : [];

    /// <summary>
    /// Creates an <see cref="HttpClient"/> that does not follow redirects, so every hop of the flow can be
    /// inspected and its cookies carried forward explicitly — the way a spec plays the browser.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateBrowser() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    /// <summary>
    /// Starts the provider challenge at <paramref name="path"/> and answers it on the callback, exactly as
    /// the browser and the identity provider would between them.
    /// </summary>
    /// <param name="browser">The client playing the browser.</param>
    /// <param name="path">The path that starts the challenge (an invitation URL or a login endpoint).</param>
    /// <param name="extraCallbackCookie">An additional cookie pair the browser presents on the callback only.</param>
    /// <returns>The whole round trip: both responses and the cookies each one set.</returns>
    public async Task<ProviderSignIn> SignInThroughProvider(HttpClient browser, string path, string? extraCallbackCookie = null)
    {
        var challenge = await browser.GetAsync(path);
        var challengeCookies = CookiesFrom(challenge);
        var state = ExtractState(challenge.Headers.Location);

        using var callbackRequest = new HttpRequestMessage(HttpMethod.Get, $"/signin-{ProviderScheme}?code=test-code&state={state}");
        var callbackCookies = challengeCookies.ToList();
        if (extraCallbackCookie is not null)
        {
            callbackCookies.Add(extraCallbackCookie);
        }

        if (callbackCookies.Count > 0)
        {
            callbackRequest.Headers.Add("Cookie", string.Join("; ", callbackCookies));
        }

        var callback = await browser.SendAsync(callbackRequest);
        return new ProviderSignIn(challenge, callback, challengeCookies, CookiesFrom(callback));
    }

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // The Development appsettings ship a placeholder Microsoft provider; running as Production keeps
        // the configured TestIdp provider the invitation's only one, so the challenge goes straight to it.
        builder.UseEnvironment("Production");

        // Provider registration happens inside Program before deferred configuration callbacks run, so the
        // configuration is supplied through settings - those reach WebApplication.CreateBuilder itself and
        // are visible when the authentication stack reads them at startup.
        foreach (var (key, value) in new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Invite:PublicKeyPem"] = InviteKeyPair.PublicKeyPem,
            [$"{C.AuthProxy.SectionKey}:Invite:ExchangeUrl"] = ExchangeUrl,
            [$"{C.AuthProxy.SectionKey}:Invite:Lobby:Frontend:BaseUrl"] = LobbyUrl,
            [$"{C.AuthProxy.SectionKey}:Invite:SubjectAlreadyExistsUrl"] = SubjectAlreadyExistsUrl,
            [$"{C.AuthProxy.SectionKey}:Invite:TenantClaim"] = TenantClaim,
            [$"{C.AuthProxy.SectionKey}:Invite:AppendInvitationIdToQueryString"] = "true",
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,
            [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:Name"] = ProviderName,
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:AuthorizationEndpoint"] = "http://idp.test/authorize",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:TokenEndpoint"] = "http://idp.test/token",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:UserInformationEndpoint"] = "http://idp.test/user",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientId"] = "test-client",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClientSecret"] = "test-secret",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClaimMappings:sub"] = "id",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClaimMappings:email"] = "email",
            [$"{C.Authentication.SectionKey}:OAuthProviders:0:ClaimMappings:email_verified"] = "email_verified",
        })
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureTestServices(services =>
        {
            // The identity provider's back channel - the token and user-information endpoints the OAuth
            // handler calls during the real handshake.
            services.PostConfigure<OAuthOptions>(ProviderScheme, options =>
                options.Backchannel = new HttpClient(new FakeIdentityProvider()) { Timeout = TimeSpan.FromSeconds(10) });

            // Everything AuthProxy itself calls out to: the invitation exchange and the identity backend.
            services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(request =>
            {
                var url = request.RequestUri?.ToString() ?? string.Empty;

                if (url.StartsWith(ExchangeUrl, StringComparison.OrdinalIgnoreCase))
                {
                    Interlocked.Increment(ref _exchangeCallCount);
                    return new HttpResponseMessage(ExchangeStatusCode);
                }

                if (url.StartsWith(IdentityBackendBaseUrl, StringComparison.OrdinalIgnoreCase))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(/*lang=json,strict*/ "{\"displayName\":\"Test User\"}")
                    };
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }));
        });
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(_pagesPath))
        {
            Directory.Delete(_pagesPath, recursive: true);
        }
    }

    static string ExtractState(Uri? location)
    {
        foreach (var pair in (location?.Query ?? string.Empty).TrimStart('?').Split('&'))
        {
            if (pair.StartsWith("state=", StringComparison.Ordinal))
            {
                return pair["state=".Length..];
            }
        }

        throw new InvalidOperationException($"No state parameter on the challenge redirect '{location}'");
    }

    /// <summary>One full provider round trip: the challenge, the callback, and the cookies each set.</summary>
    /// <param name="Challenge">The response that redirected the browser to the identity provider.</param>
    /// <param name="Callback">The response answering the provider callback.</param>
    /// <param name="ChallengeCookies">The cookie pairs the challenge set.</param>
    /// <param name="CallbackCookies">The cookie pairs the callback set.</param>
    public sealed record ProviderSignIn(
        HttpResponseMessage Challenge,
        HttpResponseMessage Callback,
        IReadOnlyList<string> ChallengeCookies,
        IReadOnlyList<string> CallbackCookies);

    sealed class FakeIdentityProvider : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri?.ToString() ?? string.Empty;

            if (url.StartsWith("http://idp.test/token", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        /*lang=json,strict*/ "{\"access_token\":\"test-access-token\",\"token_type\":\"Bearer\"}",
                        System.Text.Encoding.UTF8,
                        "application/json")
                });
            }

            if (url.StartsWith("http://idp.test/user", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        /*lang=json,strict*/ "{\"id\":\"provider-user-1\",\"email\":\"invitee@example.com\",\"email_verified\":\"true\"}",
                        System.Text.Encoding.UTF8,
                        "application/json")
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    sealed class TestHttpClientFactory(Func<HttpRequestMessage, HttpResponseMessage> handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new DispatchingHandler(handler)) { Timeout = TimeSpan.FromSeconds(10) };

        sealed class DispatchingHandler(Func<HttpRequestMessage, HttpResponseMessage> handler) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                Task.FromResult(handler(request));
        }
    }
}

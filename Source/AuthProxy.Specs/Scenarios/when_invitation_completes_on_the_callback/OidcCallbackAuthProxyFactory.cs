// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Scenarios.when_invitation_completes_on_the_callback;

/// <summary>
/// WebApplicationFactory that drives the real OIDC authentication handler - state, correlation and nonce
/// cookies, framework token validation, and the signed two-stage attested invitation protocol - against a
/// faked identity provider back channel: discovery document, JWKS, token and userinfo endpoints. Unlike
/// <see cref="CallbackAuthProxyFactory"/>, which exercises the OAuth2 handler, this is the OIDC sibling the
/// attested callback path had no coverage for.
/// </summary>
/// <remarks>
/// The provider handshake is driven for real: AuthProxy generates its own state, correlation cookie and
/// nonce; the fake back channel signs an id_token carrying whatever <c language="text">nonce</c> the challenge actually
/// generated, and a real signature/issuer/audience/nonce/at_hash validation runs against it. Nothing
/// fabricates the invitation capability binding a session carries - a session only carries it because the
/// challenge that established it bound it, exactly as production does.
/// </remarks>
public class OidcCallbackAuthProxyFactory : WebApplicationFactory<Program>
{
    public const string ProviderName = "TestOidc";
    public const string ProviderScheme = "testoidc";
    public const string Authority = "https://idp.test";
    public const string StageUrl = "https://exchange.test/invites/stage";
    public const string ExchangeUrl = "https://exchange.test/invites/exchange";
    public const string LobbyUrl = "http://lobby.test/";
    public const string TenantId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    public const string TenantClaim = "tenant_id";
    public const string CanonicalProviderKey = "testoidc";
    public const string SessionCookieName = ".Cratis.AuthProxy.Auth.v2";
    public const string DefaultSubject = "oidc-subject-1";
    public const string DefaultEmail = "invitee@example.com";
    public const string DefaultAssurance = "urn:mace:incommon:iap:silver";
    public const string AttestationIssuer = "https://authproxy.test";
    public const string AttestationAudience = "oidc-callback-spec";

    const string AttestationKeyId = "oidc-callback-spec-key";

    readonly string _pagesPath = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
    readonly RSA _idpSigningKey = RSA.Create(2048);
    readonly string _idpKeyId = Guid.NewGuid().ToString("N");
    readonly HttpClient _idpBackchannel;
    readonly RSA _attestationSigningKey = RSA.Create(2048);
    readonly string _attestationPrivateKeyPem;
    readonly RsaSecurityKey _attestationVerificationKey;
    readonly Lock _calls = new();
    readonly List<AttestedCall> _stageCalls = [];
    readonly List<AttestedCall> _exchangeCalls = [];

    /// <summary>
    /// The nonce only ever appears in the authorize redirect's query string - never in the token request -
    /// so it is captured there and handed to the fake token endpoint out of band, exactly as a real identity
    /// provider would have remembered the nonce it was challenged with for this authorization code.
    /// </summary>
    string _pendingNonce = string.Empty;

    /// <summary>Initializes a new instance of the <see cref="OidcCallbackAuthProxyFactory"/> class.</summary>
    public OidcCallbackAuthProxyFactory()
    {
        Directory.CreateDirectory(_pagesPath);
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-expired.html"), "<html><body><h1>Invitation Expired</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-invalid.html"), "<html><body><h1>Invitation Invalid</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-select-provider.html"), "<html><body><h1>Select Provider</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-email-mismatch.html"), "<html><body><h1>Email Mismatch</h1></body></html>");
        File.WriteAllText(Path.Combine(_pagesPath, "invitation-email-unavailable.html"), "<html><body><h1>Email Unavailable</h1></body></html>");

        _attestationPrivateKeyPem = _attestationSigningKey.ExportPkcs8PrivateKeyPem();

        // One long-lived verification key, built from exported parameters rather than a live RSA instance:
        // Microsoft.IdentityModel caches signature providers per security key, so a per-call key wrapping a
        // disposed RSA makes the second validation in a specification fail against a perfectly good signature.
        _attestationVerificationKey = new RsaSecurityKey(_attestationSigningKey.ExportParameters(false)) { KeyId = AttestationKeyId };

        // Owned by the factory, not by the options: nothing in the OIDC options pipeline disposes an
        // externally supplied Backchannel, and the ConfigurationManager below keeps using it for the whole
        // fixture lifetime.
        _idpBackchannel = new HttpClient(new FakeIdentityProvider(this)) { Timeout = TimeSpan.FromSeconds(10) };
    }

    public (RsaSecurityKey PrivateKey, string PublicKeyPem) InviteKeyPair { get; } = TokenFixture.GenerateKeyPair();

    public int ExchangeCallCount
    {
        get
        {
            lock (_calls)
            {
                return _exchangeCalls.Count;
            }
        }
    }

    /// <summary>Gets the calls the proxy made to the staging endpoint, in order.</summary>
    public IReadOnlyList<AttestedCall> StageCalls
    {
        get
        {
            lock (_calls)
            {
                return [.. _stageCalls];
            }
        }
    }

    /// <summary>Gets the calls the proxy made to the completion exchange endpoint, in order.</summary>
    public IReadOnlyList<AttestedCall> ExchangeCalls
    {
        get
        {
            lock (_calls)
            {
                return [.. _exchangeCalls];
            }
        }
    }

    /// <summary>Gets or sets the claims the fake identity provider's id_token and userinfo response carry, beyond <c language="text">sub</c>/<c language="text">nonce</c>/<c language="text">at_hash</c>.</summary>
    public IReadOnlyDictionary<string, string> IdentityClaims { get; set; } = DefaultIdentityClaims();

    /// <summary>Gets or sets the provider subject the fake identity provider asserts.</summary>
    public string Subject { get; set; } = DefaultSubject;

    /// <summary>
    /// Gets or sets a value indicating whether the fake identity provider signs the id_token with a nonce
    /// that does not match the one the challenge actually generated, for proving nonce validation is real.
    /// </summary>
    public bool SignWithWrongNonce { get; set; }

    /// <summary>
    /// Extracts the reusable <c language="text">name=value</c> cookie pairs a response set, skipping deletions.
    /// </summary>
    /// <param name="response">The response whose cookies to collect.</param>
    /// <returns>The cookie pairs, ready for a <c language="text">Cookie</c> request header.</returns>
    public static IReadOnlyList<string> CookiesFrom(HttpResponseMessage response) =>
        CallbackAuthProxyFactory.CookiesFrom(response);

    /// <summary>
    /// Computes the base64url-encoded SHA-256 capability hash of an invitation, independently of the proxy.
    /// </summary>
    /// <param name="capability">The invitation capability.</param>
    /// <returns>The capability hash the attestation is expected to carry.</returns>
    public static string CapabilityHashOf(string capability) =>
        Base64UrlEncode(SHA256.HashData(Encoding.UTF8.GetBytes(capability)));

    /// <summary>
    /// Restores every mutable knob to its default and forgets the calls recorded so far, so one specification
    /// can never inherit another's identity provider behavior.
    /// </summary>
    public void Reset()
    {
        Subject = DefaultSubject;
        IdentityClaims = DefaultIdentityClaims();
        SignWithWrongNonce = false;
        lock (_calls)
        {
            _stageCalls.Clear();
            _exchangeCalls.Clear();
        }
    }

    /// <summary>
    /// Validates an attestation the way the receiving backend must: against the exact signing key, issuer,
    /// audience, algorithm and lifetime the proxy is configured with, never by decoding it unverified.
    /// </summary>
    /// <param name="attestation">The attestation bearer token to validate.</param>
    /// <returns>The validated claims.</returns>
    /// <exception cref="InvalidOperationException">Thrown when the attestation does not validate.</exception>
    public async Task<IReadOnlyDictionary<string, string>> ValidateAttestation(string attestation)
    {
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(attestation, new TokenValidationParameters
        {
            ValidIssuer = AttestationIssuer,
            ValidAudience = AttestationAudience,
            IssuerSigningKey = _attestationVerificationKey,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
        });

        if (!result.IsValid)
        {
            throw new InvalidOperationException("The attestation did not validate against the configured key, issuer and audience.", result.Exception);
        }

        return result.ClaimsIdentity.Claims.ToDictionary(claim => claim.Type, claim => claim.Value, StringComparer.Ordinal);
    }

    /// <summary>
    /// Creates an <see cref="HttpClient"/> that does not follow redirects, so every hop of the flow can be
    /// inspected and its cookies carried forward explicitly - the way a spec plays the browser.
    /// </summary>
    /// <returns>A configured <see cref="HttpClient"/>.</returns>
    public HttpClient CreateBrowser() =>
        CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });

    /// <summary>
    /// Starts the OIDC challenge at <paramref name="path"/> and answers it on the callback with a fake
    /// identity provider round trip, exactly as the browser and a real OIDC provider would between them.
    /// </summary>
    /// <param name="browser">The client playing the browser.</param>
    /// <param name="path">The path that starts the challenge (an invitation URL or a login endpoint).</param>
    /// <param name="extraCallbackCookie">An additional cookie pair the browser presents on the callback only.</param>
    /// <param name="transformCallbackCookies">
    /// An optional transform applied to the challenge cookies before they are presented on the callback, so a
    /// spec can tamper with one exact cookie (e.g. corrupt the protected invitation-entry state) while every
    /// other real handshake cookie - correlation, nonce, state - still round-trips unmodified.
    /// </param>
    /// <returns>The whole round trip: both responses and the cookies each one set.</returns>
    public async Task<ProviderSignIn> SignInThroughProvider(
        HttpClient browser,
        string path,
        string? extraCallbackCookie = null,
        Func<IReadOnlyList<string>, IReadOnlyList<string>>? transformCallbackCookies = null)
    {
        var challenge = await browser.GetAsync(path);
        var challengeCookies = CookiesFrom(challenge);
        var state = ExtractQueryParameter(challenge.Headers.Location, "state");
        _pendingNonce = ExtractQueryParameter(challenge.Headers.Location, "nonce");
        var code = $"test-code-{Guid.NewGuid():N}";

        var callbackCookies = (transformCallbackCookies ?? (cookies => cookies))(challengeCookies).ToList();
        if (extraCallbackCookie is not null)
        {
            callbackCookies.Add(extraCallbackCookie);
        }

        using var callbackRequest = new HttpRequestMessage(HttpMethod.Get, $"/signin-{ProviderScheme}?code={code}&state={state}");
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
        // the configured OIDC provider the invitation's only one, so the challenge goes straight to it.
        builder.UseEnvironment("Production");

        foreach (var (key, value) in new Dictionary<string, string?>
        {
            [$"{C.AuthProxy.SectionKey}:Invite:PublicKeyPem"] = InviteKeyPair.PublicKeyPem,
            [$"{C.AuthProxy.SectionKey}:Invite:ExchangeUrl"] = ExchangeUrl,
            [$"{C.AuthProxy.SectionKey}:Invite:StageUrl"] = StageUrl,
            [$"{C.AuthProxy.SectionKey}:Invite:EmailClaim"] = "email",
            [$"{C.AuthProxy.SectionKey}:Invite:TenantClaim"] = TenantClaim,
            [$"{C.AuthProxy.SectionKey}:Invite:Lobby:Frontend:BaseUrl"] = LobbyUrl,
            [$"{C.AuthProxy.SectionKey}:Invite:MatchingTenantInvitationDestination"] = nameof(C.InvitationCompletionDestination.Lobby),
            [$"{C.AuthProxy.SectionKey}:Invite:AppendInvitationIdToQueryString"] = "true",
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:Issuer"] = AttestationIssuer,
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:Audience"] = AttestationAudience,
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:ActiveKeyId"] = AttestationKeyId,
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:SigningKeys:0:KeyId"] = AttestationKeyId,
            [$"{C.AuthProxy.SectionKey}:Invite:Attestation:SigningKeys:0:PrivateKeyPem"] = _attestationPrivateKeyPem,
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy"] = nameof(C.TenantSourceIdentifierResolverType.Specified),
            [$"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantId"] = TenantId,
            [$"{C.AuthProxy.SectionKey}:PagesPath"] = _pagesPath,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Name"] = ProviderName,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:Authority"] = Authority,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientId"] = "test-client",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:ClientSecret"] = "test-secret",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:InvitationCompletionEnabled"] = bool.TrueString,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:ProviderKey"] = CanonicalProviderKey,
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:SubjectClaimType"] = "sub",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:EmailClaimType"] = "email",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:EmailVerifiedClaimType"] = "email_verified",
            [$"{C.Authentication.SectionKey}:OidcProviders:0:CanonicalIdentity:AssuranceClaimType"] = "acr",
        })
        {
            builder.UseSetting(key, value);
        }

        builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<OpenIdConnectOptions>(ProviderScheme, options =>
            {
                // The framework's own OpenIdConnectPostConfigureOptions already built a ConfigurationManager
                // bound to the real backchannel by the time this later PostConfigure runs, so the manager
                // itself - not just the Backchannel property - has to be rebuilt against the fake identity
                // provider for discovery/JWKS to resolve against it.
                options.Backchannel = _idpBackchannel;
                options.RequireHttpsMetadata = true;
                options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    $"{Authority}/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever(_idpBackchannel) { RequireHttps = true });
            });

            services.AddSingleton<IHttpClientFactory>(new TestHttpClientFactory(async (request, cancellationToken) =>
            {
                var url = request.RequestUri?.ToString() ?? string.Empty;

                if (url.StartsWith(StageUrl, StringComparison.OrdinalIgnoreCase))
                {
                    await Record(_stageCalls, request, cancellationToken);
                    return new HttpResponseMessage(HttpStatusCode.OK);
                }

                if (url.StartsWith(ExchangeUrl, StringComparison.OrdinalIgnoreCase))
                {
                    await Record(_exchangeCalls, request, cancellationToken);
                    return new HttpResponseMessage(HttpStatusCode.OK);
                }

                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }));
        });
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            _idpBackchannel.Dispose();
            _idpSigningKey.Dispose();
            _attestationSigningKey.Dispose();
            if (Directory.Exists(_pagesPath))
            {
                Directory.Delete(_pagesPath, recursive: true);
            }
        }
    }

    static string ExtractQueryParameter(Uri? location, string name)
    {
        foreach (var pair in (location?.Query ?? string.Empty).TrimStart('?').Split('&'))
        {
            var parts = pair.Split('=', 2);
            if (parts.Length == 2 && string.Equals(Uri.UnescapeDataString(parts[0]), name, StringComparison.Ordinal))
            {
                return parts[1];
            }
        }

        throw new InvalidOperationException($"No '{name}' parameter on the challenge redirect '{location}'");
    }

    static string Base64UrlEncode(byte[] bytes) => Base64UrlEncoder.Encode(bytes);

    static Dictionary<string, string> DefaultIdentityClaims() => new()
    {
        ["email"] = DefaultEmail,
        ["email_verified"] = "true",
        ["acr"] = DefaultAssurance,
    };

    /// <summary>
    /// One call the proxy made to an invitation endpoint, as the receiving backend would have seen it.
    /// </summary>
    /// <param name="Bearer">The attestation presented in the <c language="text">Authorization</c> header.</param>
    /// <param name="Body">The request body.</param>
    public sealed record AttestedCall(string Bearer, string Body);

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

    sealed class FakeIdentityProvider(OidcCallbackAuthProxyFactory factory) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(Respond(request));

        HttpResponseMessage Respond(HttpRequestMessage request)
        {
            var url = request.RequestUri?.ToString() ?? string.Empty;

            if (url.StartsWith($"{Authority}/.well-known/openid-configuration", StringComparison.OrdinalIgnoreCase))
            {
                return JsonResponse(new
                {
                    issuer = Authority,
                    authorization_endpoint = $"{Authority}/authorize",
                    token_endpoint = $"{Authority}/token",
                    userinfo_endpoint = $"{Authority}/userinfo",
                    jwks_uri = $"{Authority}/jwks",
                    response_types_supported = new[] { "code" },
                    subject_types_supported = new[] { "public" },
                    id_token_signing_alg_values_supported = new[] { SecurityAlgorithms.RsaSha256 },
                });
            }

            if (url.StartsWith($"{Authority}/jwks", StringComparison.OrdinalIgnoreCase))
            {
                var parameters = factory._idpSigningKey.ExportParameters(false);
                return JsonResponse(new
                {
                    keys = new[]
                    {
                        new
                        {
                            kty = "RSA",
                            use = "sig",
                            kid = factory._idpKeyId,
                            alg = SecurityAlgorithms.RsaSha256,
                            n = Base64UrlEncode(parameters.Modulus!),
                            e = Base64UrlEncode(parameters.Exponent!),
                        },
                    },
                });
            }

            if (url.StartsWith($"{Authority}/token", StringComparison.OrdinalIgnoreCase))
            {
                var accessToken = $"test-access-token-{Guid.NewGuid():N}";
                var idToken = factory.CreateIdToken(accessToken, factory.SignWithWrongNonce ? $"wrong-{factory._pendingNonce}" : factory._pendingNonce);
                return JsonResponse(new
                {
                    access_token = accessToken,
                    id_token = idToken,
                    token_type = "Bearer",
                    expires_in = 3600,
                });
            }

            if (url.StartsWith($"{Authority}/userinfo", StringComparison.OrdinalIgnoreCase))
            {
                var claims = new Dictionary<string, string>(factory.IdentityClaims) { ["sub"] = factory.Subject };
                return JsonResponse(claims);
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        static HttpResponseMessage JsonResponse(object payload) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json"),
        };
    }

    async Task Record(List<AttestedCall> calls, HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var call = new AttestedCall(
            request.Headers.Authorization?.Parameter ?? string.Empty,
            request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken));
        lock (_calls)
        {
            calls.Add(call);
        }
    }

    string CreateIdToken(string accessToken, string nonce)
    {
        var claims = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var (type, value) in IdentityClaims)
        {
            claims[type] = value;
        }

        claims["sub"] = Subject;
        claims["nonce"] = nonce;
        claims["at_hash"] = ComputeAtHash(accessToken);

        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = Authority,
            Audience = "test-client",
            Claims = claims,
            Expires = DateTime.UtcNow.AddMinutes(10),
            NotBefore = DateTime.UtcNow.AddMinutes(-1),
            IssuedAt = DateTime.UtcNow,
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(_idpSigningKey) { KeyId = _idpKeyId }, SecurityAlgorithms.RsaSha256),
        };
        return handler.CreateToken(descriptor);
    }

    static string ComputeAtHash(string accessToken)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
        var half = hash.AsSpan(0, hash.Length / 2).ToArray();
        return Base64UrlEncode(half);
    }

    sealed class TestHttpClientFactory(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) =>
            new(new DispatchingHandler(handler)) { Timeout = TimeSpan.FromSeconds(10) };

        sealed class DispatchingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                handler(request, cancellationToken);
        }
    }
}

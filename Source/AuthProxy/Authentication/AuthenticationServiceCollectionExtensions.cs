// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Http.Headers;
using Cratis.AuthProxy.Links;
using Cratis.AuthProxy.SignIns;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using C = Cratis.AuthProxy.Configuration;

namespace Cratis.AuthProxy.Authentication;

/// <summary>
/// Extension methods for registering authentication services on <see cref="WebApplicationBuilder"/>.
/// </summary>
public static class AuthenticationServiceCollectionExtensions
{
    /// <summary>
    /// The <see cref="AuthenticationProperties"/> item key recording which provider scheme established the
    /// session. It is persisted into the authentication cookie on sign-in so a later RP-initiated logout can
    /// resolve the correct identity provider's end-session endpoint.
    /// </summary>
    public const string AuthenticationSchemeStateKey = "Cratis.AuthProxy.AuthenticationScheme";

    const string ValidatedIssuerStateKey = "Cratis.AuthProxy.ValidatedIssuer";

    /// <summary>
    /// Registers cookie authentication, all configured OIDC providers, all configured OAuth providers,
    /// and (optionally) JWT Bearer for machine-to-machine flows.
    /// </summary>
    /// <param name="builder">The <see cref="WebApplicationBuilder"/> to configure.</param>
    /// <returns>The same <see cref="WebApplicationBuilder"/> for chaining.</returns>
    public static WebApplicationBuilder AddIngressAuthentication(this WebApplicationBuilder builder)
    {
        var jwtSection = builder.Configuration.GetSection($"{C.Authentication.SectionKey}:JwtBearer");
        var hasJwtBearer = jwtSection.Exists();

        var sessionConfig = builder.Configuration
            .GetSection(C.Session.SectionKey)
            .Get<C.Session>() ?? new();

        var authBuilder = builder.Services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = ClientCredentialsDefaults.CompositeAuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddPolicyScheme(
                ClientCredentialsDefaults.CompositeAuthenticationScheme,
                ClientCredentialsDefaults.CompositeAuthenticationScheme,
                options => options.ForwardDefaultSelector = context => ResolveAuthenticationScheme(context, hasJwtBearer))
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options => ConfigureCookieOptions(options, sessionConfig))
            .AddScheme<AuthenticationSchemeOptions, ClientCredentialsBearerAuthenticationHandler>(
                ClientCredentialsDefaults.AuthenticationScheme,
                _ => { });

        var authConfig = builder.Configuration
            .GetSection(C.Authentication.SectionKey)
            .Get<C.Authentication>() ?? new();

        RegisterOidcProviders(authBuilder, authConfig.OidcProviders);
        RegisterOAuthProviders(authBuilder, authConfig.OAuthProviders);

        builder.Services.AddSingleton<ClientCredentialsServiceResolver>();
        builder.Services.AddSingleton<ClientCredentialsVerifier>();
        builder.Services.AddSingleton<ClientCredentialsTokenProtector>();
        builder.Services.AddSingleton<ClientCredentialsGrantService>();
        builder.Services.AddSingleton<IEndSessionEndpointResolver, EndSessionEndpointResolver>();
        builder.Services.AddSingleton<ICanonicalIdentityResolver, CanonicalIdentityResolver>();
        builder.Services.AddSingleton<IValidateOptions<C.Authentication>, CanonicalIdentityConfigurationValidator>();
        builder.Services.AddHttpClient(nameof(ClientCredentialsVerifier), client => client.Timeout = TimeSpan.FromSeconds(10));

        if (jwtSection.Exists())
        {
            authBuilder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, jwtSection.Bind);
        }

        builder.Services.AddAuthorizationBuilder()
            .SetDefaultPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                .RequireAuthenticatedUser()
                .Build());

        return builder;
    }

    static string ResolveAuthenticationScheme(HttpContext context, bool hasJwtBearer)
    {
        var authorization = context.Request.Headers.Authorization.ToString();
        if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = authorization["Bearer ".Length..].Trim();
            var tokenProtector = context.RequestServices.GetRequiredService<ClientCredentialsTokenProtector>();
            if (tokenProtector.TryValidate(token, out var payload))
            {
                context.Items[ClientCredentialsDefaults.ValidatedTokenPayloadItemKey] = payload;
                return ClientCredentialsDefaults.AuthenticationScheme;
            }

            if (hasJwtBearer)
            {
                return JwtBearerDefaults.AuthenticationScheme;
            }
        }

        return CookieAuthenticationDefaults.AuthenticationScheme;
    }

    static void ConfigureCookieOptions(CookieAuthenticationOptions options, C.Session session)
    {
        options.Cookie.HttpOnly = true;
        options.Cookie.Name = ".Cratis.AuthProxy.Auth.v2";
        options.Cookie.SameSite = SameSiteMode.Lax;

        // Mark the cookie Secure whenever the request itself is HTTPS — the forwarded-headers middleware
        // makes this reflect the original scheme behind a TLS-terminating ingress — while still supporting
        // local HTTP development flows.
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

        // The cookie itself stays session-scoped (no persistent Expires) — closing the browser ends the
        // session. The encrypted ticket additionally carries a bounded lifetime so even a browser session
        // that never closes must re-authenticate with the identity provider periodically; with sliding
        // expiration disabled (the default) that lifetime is absolute and activity cannot extend it.
        options.ExpireTimeSpan = session.Lifetime > TimeSpan.Zero ? session.Lifetime : C.Session.DefaultLifetime;
        options.SlidingExpiration = session.SlidingExpiration;

        var existingValidatePrincipal = options.Events.OnValidatePrincipal;
        options.Events.OnValidatePrincipal = async context =>
        {
            await existingValidatePrincipal(context);
            if (context.Principal is not null)
            {
                await ValidateCanonicalSession(context);
            }
        };

        // Redirect unauthenticated users to the provider selection page (multiple providers)
        // or directly to the single provider login endpoint.
        options.Events.OnRedirectToLogin = async ctx =>
        {
            var authConfig = ctx.HttpContext.RequestServices
                .GetRequiredService<IOptionsMonitor<C.Authentication>>()
                .CurrentValue;

            var returnUrl = ctx.HttpContext.IsAuthenticationBootstrap()
                ? "/"
                : ctx.HttpContext.GetPathAndQuery();

            if (authConfig.TotalProviderCount > 1)
            {
                ctx.Response.Redirect($"{WellKnownPaths.LoginPage}?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return;
            }

            if (authConfig.OidcProviders.Count == 1)
            {
                var scheme = OidcProviderScheme.FromName(authConfig.OidcProviders[0].Name);
                ctx.Response.Redirect($"{WellKnownPaths.LoginPrefix}/{scheme}?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return;
            }

            if (authConfig.OAuthProviders.Count == 1)
            {
                var scheme = OidcProviderScheme.FromName(authConfig.OAuthProviders[0].Name);
                ctx.Response.Redirect($"{WellKnownPaths.LoginPrefix}/{scheme}?returnUrl={Uri.EscapeDataString(returnUrl)}");
                return;
            }

            // No providers configured — return 500 with diagnostic message
            ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await ctx.Response.WriteAsync(
                "Authentication is not configured. " +
                "Please configure at least one OIDC or OAuth provider (GitHub, Microsoft, Google, Apple) " +
                "via environment variables or application configuration.");
        };
    }

    static void RegisterOidcProviders(AuthenticationBuilder authBuilder, IList<C.OidcProvider> providers)
    {
        foreach (var provider in providers)
        {
            var scheme = OidcProviderScheme.FromName(provider.Name);
            var capturedProvider = provider;
            authBuilder.AddOpenIdConnect(scheme, options =>
            {
                options.Authority = capturedProvider.Authority;
                options.ClientId = capturedProvider.ClientId;
                options.ClientSecret = capturedProvider.ClientSecret;
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                if (capturedProvider.CanonicalIdentity is not null)
                {
                    // Canonical providers select one exact protocol claim name. Preserve those names instead
                    // of applying the legacy WS-* inbound mapping; noncanonical providers remain unchanged.
                    options.MapInboundClaims = false;
                }

                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");

                foreach (var scope in capturedProvider.Scopes)
                {
                    options.Scope.Add(scope);
                }

                options.CallbackPath = $"/signin-{scheme}";

                // Lax + SameAsRequest keeps the handshake cookies flowing across the provider redirect,
                // marks them Secure whenever the site runs on HTTPS, and still supports local HTTP
                // development callback flows.
                options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.NonceCookie.SameSite = SameSiteMode.Lax;
                options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

                // Keep the transient handshake cookies at the root path (they otherwise default to the
                // callback path) so the browser sends them on the logout request and they can be cleared
                // there instead of accumulating from abandoned sign-in attempts.
                options.CorrelationCookie.Path = "/";
                options.NonceCookie.Path = "/";

                options.Events = new OpenIdConnectEvents
                {
                    OnTokenValidated = context =>
                    {
                        context.Properties.Items[ValidatedIssuerStateKey] = context.SecurityToken.Issuer;
                        return Task.CompletedTask;
                    },
                    OnTicketReceived = context => HandleTicketReceived(
                        context,
                        () => CanonicalSessionRegistrationFingerprint.Create(
                            scheme,
                            capturedProvider,
                            (OpenIdConnectOptions)context.Options))
                };
            });
        }
    }

    static void RegisterOAuthProviders(AuthenticationBuilder authBuilder, IList<C.OAuthProvider> providers)
    {
        foreach (var provider in providers)
        {
            var scheme = OidcProviderScheme.FromName(provider.Name);
            var capturedProvider = provider;

            authBuilder.AddOAuth(scheme, options =>
            {
                options.AuthorizationEndpoint = capturedProvider.AuthorizationEndpoint;
                options.TokenEndpoint = capturedProvider.TokenEndpoint;
                options.UserInformationEndpoint = capturedProvider.UserInformationEndpoint;
                options.ClientId = capturedProvider.ClientId;
                options.ClientSecret = capturedProvider.ClientSecret;
                options.CallbackPath = $"/signin-{scheme}";
                options.SaveTokens = true;

                // Lax + SameAsRequest keeps the handshake cookie flowing across the provider redirect,
                // marks it Secure whenever the site runs on HTTPS, and still supports local HTTP
                // development callback flows.
                options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;

                // Keep the transient correlation cookie at the root path (it otherwise defaults to the
                // callback path) so the browser sends it on the logout request and it can be cleared there
                // instead of accumulating from abandoned sign-in attempts.
                options.CorrelationCookie.Path = "/";

                foreach (var scope in capturedProvider.Scopes)
                {
                    options.Scope.Add(scope);
                }

                foreach (var mapping in capturedProvider.ClaimMappings)
                {
                    options.ClaimActions.MapJsonKey(mapping.Key, mapping.Value);
                }

                options.Events = new OAuthEvents
                {
                    OnCreatingTicket = async ctx =>
                    {
                        var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("Cratis-AuthProxy", "1.0"));

                        var response = await ctx.Backchannel.SendAsync(request, ctx.HttpContext.RequestAborted);
                        response.EnsureSuccessStatusCode();

                        using var user = JsonDocument.Parse(
                            await response.Content.ReadAsStringAsync(ctx.HttpContext.RequestAborted));
                        ctx.RunClaimActions(user.RootElement);
                    },
                    OnTicketReceived = context => HandleTicketReceived(
                        context,
                        () => CanonicalSessionRegistrationFingerprint.Create(
                            scheme,
                            capturedProvider,
                            (OAuthOptions)context.Options))
                };
            });
        }
    }

    /// <summary>
    /// Shared provider-callback handler. In the session-preserving link flow it captures the freshly
    /// authenticated subject and posts it to the application <em>without</em> signing the new identity in,
    /// so the user's primary session is preserved; otherwise it is a genuine sign-in — a logged-out user has
    /// completed an identity-provider login and a fresh session is about to be established — so it records the
    /// authenticating provider scheme for later RP-initiated logout, notifies the application of the sign-in,
    /// and applies the tenant post-authentication redirect resolution used by
    /// the normal login flow.
    /// </summary>
    /// <param name="context">The ticket-received context.</param>
    /// <param name="createRegistrationFingerprint">Creates the fingerprint that binds a canonical session to its provider registration.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    /// <remarks>
    /// This handler only runs when a provider callback delivers a fresh ticket — that is, on the exact
    /// logged-out to signed-in transition. A request that reuses an existing session cookie never reaches it,
    /// so a sign-in is notified once per real sign-in and never on ordinary proxied traffic.
    /// </remarks>
    static async Task HandleTicketReceived(TicketReceivedContext context, Func<string> createRegistrationFingerprint)
    {
        var canonicalIdentityResolver = context.HttpContext.RequestServices.GetRequiredService<ICanonicalIdentityResolver>();
        string? validatedIssuer = null;
        context.Properties?.Items.TryGetValue(ValidatedIssuerStateKey, out validatedIssuer);
        var canonicalResolution = canonicalIdentityResolver.Resolve(
            context.Principal,
            context.Scheme.Name,
            validatedIssuer,
            isFreshAuthentication: true);
        context.Properties?.Items.Remove(ValidatedIssuerStateKey);
        context.Properties?.Items.Remove(CanonicalSessionRegistrationFingerprint.StateKey);
        if (canonicalResolution.IsConfigured
            && (!canonicalResolution.Succeeded || canonicalResolution.Principal is null))
        {
            context.Fail("Canonical federated identity could not be resolved.");
            return;
        }

        if (canonicalResolution.Principal is not null)
        {
            context.Principal = canonicalResolution.Principal;
        }

        if (context.Properties is not null
            && context.Properties.Items.TryGetValue(LinkMiddleware.LinkModePropertyKey, out var linkMode)
            && linkMode == "true")
        {
            var exchanger = context.HttpContext.RequestServices.GetRequiredService<ILinkSubjectExchanger>();
            await exchanger.Exchange(context.Principal, context.Properties);

            // Short-circuit before the RemoteAuthenticationHandler signs the ticket into the cookie scheme:
            // the linked identity must never replace the primary session. Hand the browser back to the app.
            context.Response.Redirect(context.Properties.RedirectUri ?? "/");
            context.HandleResponse();
            return;
        }

        if (canonicalResolution.IsConfigured)
        {
            context.Properties!.Items[CanonicalSessionRegistrationFingerprint.StateKey] = createRegistrationFingerprint();
        }

        // A non-link ticket means a real sign-in is completing. Record which provider established this session so
        // a later RP-initiated logout can target the correct identity provider's end-session endpoint (persisted
        // into the auth cookie by the RemoteAuthenticationHandler that signs the ticket in), and notify the
        // application of the sign-in — scoped here to the logged-out to signed-in transition rather than every
        // proxied request. The notification never throws, so a notification failure can never break the sign-in.
        context.Properties?.Items.TryAdd(AuthenticationSchemeStateKey, context.Scheme.Name);
        var notifier = context.HttpContext.RequestServices.GetRequiredService<ISignInNotifier>();
        await notifier.Notify(context.HttpContext, context.Principal);

        if (context.Properties is not null
            && TenantAuthenticationState.TryResolvePostAuthenticationRedirectUri(
                context.HttpContext,
                context.Properties,
                context.ReturnUri,
                out var redirectUri))
        {
            context.ReturnUri = redirectUri;
        }
    }

    static async Task ValidateCanonicalSession(CookieValidatePrincipalContext context)
    {
        var reservedClaims = context.Principal!.Claims.Where(_ => CanonicalIdentityClaims.IsReserved(_.Type)).ToArray();
        var fingerprintKeys = context.Properties.Items.Keys
            .Where(_ => string.Equals(_, CanonicalSessionRegistrationFingerprint.StateKey, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (reservedClaims.Length == 0 && fingerprintKeys.Length == 0)
        {
            try
            {
                var authentication = context.HttpContext.RequestServices
                    .GetRequiredService<IOptionsMonitor<C.Authentication>>()
                    .CurrentValue;
                if (!context.Properties.Items.TryGetValue(AuthenticationSchemeStateKey, out var legacyProviderScheme)
                    || string.IsNullOrWhiteSpace(legacyProviderScheme)
                    || !IsConfiguredCanonicalProvider(authentication, legacyProviderScheme))
                {
                    return;
                }
            }
            catch (OptionsValidationException)
            {
                await RejectCanonicalSession(context);
                return;
            }

            await RejectCanonicalSession(context);
            return;
        }

        if (reservedClaims.Length == 0
            || fingerprintKeys.Length != 1
            || !string.Equals(fingerprintKeys[0], CanonicalSessionRegistrationFingerprint.StateKey, StringComparison.Ordinal)
            || !context.Properties.Items.TryGetValue(CanonicalSessionRegistrationFingerprint.StateKey, out var storedFingerprint)
            || !CanonicalSessionRegistrationFingerprint.IsWellFormed(storedFingerprint)
            || !context.Properties.Items.TryGetValue(AuthenticationSchemeStateKey, out var providerScheme)
            || string.IsNullOrWhiteSpace(providerScheme))
        {
            await RejectCanonicalSession(context);
            return;
        }

        try
        {
            var services = context.HttpContext.RequestServices;
            var resolver = services.GetRequiredService<ICanonicalIdentityResolver>();
            var resolution = resolver.Resolve(context.Principal, context.Scheme.Name);
            if (!resolution.IsConfigured
                || !resolution.Succeeded
                || resolution.Identity is null
                || !TryCreateCurrentRegistrationFingerprint(services, providerScheme, out var expectedFingerprint)
                || !string.Equals(storedFingerprint, expectedFingerprint, StringComparison.Ordinal))
            {
                await RejectCanonicalSession(context);
            }
        }
        catch (OptionsValidationException)
        {
            await RejectCanonicalSession(context);
        }
    }

    static bool IsConfiguredCanonicalProvider(C.Authentication authentication, string scheme) =>
        authentication.OidcProviders.Any(_ =>
            _.CanonicalIdentity is not null
            && string.Equals(OidcProviderScheme.FromName(_.Name), scheme, StringComparison.Ordinal))
        || authentication.OAuthProviders.Any(_ =>
            _.CanonicalIdentity is not null
            && string.Equals(OidcProviderScheme.FromName(_.Name), scheme, StringComparison.Ordinal));

    static bool TryCreateCurrentRegistrationFingerprint(IServiceProvider services, string scheme, out string fingerprint)
    {
        var authentication = services.GetRequiredService<IOptionsMonitor<C.Authentication>>().CurrentValue;
        var oidcProviders = authentication.OidcProviders
            .Where(_ => string.Equals(OidcProviderScheme.FromName(_.Name), scheme, StringComparison.Ordinal))
            .ToArray();
        var oauthProviders = authentication.OAuthProviders
            .Where(_ => string.Equals(OidcProviderScheme.FromName(_.Name), scheme, StringComparison.Ordinal))
            .ToArray();

        if (oidcProviders.Length + oauthProviders.Length != 1)
        {
            fingerprint = string.Empty;
            return false;
        }

        if (oidcProviders.Length == 1 && oidcProviders[0].CanonicalIdentity is not null)
        {
            var options = services.GetRequiredService<IOptionsMonitor<OpenIdConnectOptions>>().Get(scheme);
            fingerprint = CanonicalSessionRegistrationFingerprint.Create(scheme, oidcProviders[0], options);
            return true;
        }

        if (oauthProviders.Length == 1 && oauthProviders[0].CanonicalIdentity is not null)
        {
            var options = services.GetRequiredService<IOptionsMonitor<OAuthOptions>>().Get(scheme);
            fingerprint = CanonicalSessionRegistrationFingerprint.Create(scheme, oauthProviders[0], options);
            return true;
        }

        fingerprint = string.Empty;
        return false;
    }

    static async Task RejectCanonicalSession(CookieValidatePrincipalContext context)
    {
        context.RejectPrincipal();
        await context.HttpContext.SignOutAsync(context.Scheme.Name);
    }
}

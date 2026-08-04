// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Scenarios.when_anonymous_paths_are_configured;

/// <summary>
/// The same host with tenant selection configured and a caller who <em>is</em> signed in but has not
/// chosen a tenant — the state a signed-in user is in on their first request, and the one state in which
/// <c>TenantSelectionMiddleware</c> answers rather than forwards.
/// </summary>
public class TenantSelectionAuthProxyFactory : AuthProxyFactory
{
    /// <inheritdoc/>
    protected override IEnumerable<KeyValuePair<string, string?>> TenantResolutionSettings =>
    [
        new($"{C.AuthProxy.SectionKey}:TenantResolutions:0:Strategy", nameof(C.TenantSourceIdentifierResolverType.Selection)),
        new($"{C.AuthProxy.SectionKey}:TenantResolutions:0:Options:TenantsEndpoint", "https://tenants.test/selectable"),
    ];

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);

        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(SignedInAuthHandler.Scheme)
                .AddScheme<AuthenticationSchemeOptions, SignedInAuthHandler>(SignedInAuthHandler.Scheme, _ => { });

            services.AddSingleton<IHttpClientFactory>(new SelectableTenantsClientFactory());
        });
    }

    /// <summary>Authentication handler that authenticates every request.</summary>
    /// <param name="options">The options monitor for authentication scheme options.</param>
    /// <param name="logger">The logger factory.</param>
    /// <param name="encoder">The URL encoder.</param>
    public class SignedInAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string Scheme = "SignedInTestScheme";

        /// <inheritdoc/>
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var identity = new ClaimsIdentity([new Claim("oid", "user-id")], Scheme);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme)));
        }
    }

    /// <summary>Answers the selectable-tenants endpoint with more than one tenant, so a choice is required.</summary>
    sealed class SelectableTenantsClientFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new Handler());

        sealed class Handler : HttpMessageHandler
        {
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("""[{"id":"tenant-a","name":"Tenant A"},{"id":"tenant-b","name":"Tenant B"}]"""),
                });
        }
    }
}

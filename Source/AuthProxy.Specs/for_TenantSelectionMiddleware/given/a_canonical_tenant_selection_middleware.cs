// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.for_TenantSelectionMiddleware.given;

/// <summary>
/// Provides tenant-selection middleware configured with two canonical providers sharing a raw subject.
/// </summary>
public class a_canonical_tenant_selection_middleware : Specification
{
    protected const string TenantId = "tenant-a";

    protected CountingTenantsHandler _handler;
    protected IOptionsMonitor<C.AuthProxy> _options;

    void Establish()
    {
        _handler = new CountingTenantsHandler();
        _options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        _options.CurrentValue.Returns(new C.AuthProxy
        {
            Session = new C.Session { TenantRevalidationInterval = TimeSpan.FromMinutes(10) },
            Authentication = new C.Authentication
            {
                OAuthProviders =
                [
                    Provider("Provider A", "workforce-a", "https://identity-a.example.com"),
                    Provider("Provider B", "workforce-b", "https://identity-b.example.com")
                ]
            },
            TenantResolutions =
            [
                new C.TenantResolution
                {
                    Strategy = C.TenantSourceIdentifierResolverType.Selection,
                    Options = new SelectionOptions { TenantsEndpoint = "https://platform.example.com/api/tenants/selectable" }
                }
            ]
        });
    }

    protected TenantSelectionMiddleware CreateMiddleware(ITenantResolver tenantResolver, IMemoryCache memoryCache)
    {
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler, disposeHandler: false));
        return new TenantSelectionMiddleware(
            _ => Task.CompletedTask,
            _options,
            tenantResolver,
            clients,
            Substitute.For<IErrorPageProvider>(),
            memoryCache);
    }

    protected DefaultHttpContext ContextFor(string authenticationScheme)
    {
        var authentication = _options.CurrentValue.Authentication;
        var authenticationOptions = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationOptions.CurrentValue.Returns(authentication);
        var canonicalResolver = new CanonicalIdentityResolver(authenticationOptions);
        var context = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection()
                .AddSingleton<ICanonicalIdentityResolver>(canonicalResolver)
                .BuildServiceProvider(),
            User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("oid", "shared-subject")], authenticationScheme))
        };
        context.Request.Path = "/products";
        context.Response.Body = new MemoryStream();
        return context;
    }

    static C.OAuthProvider Provider(string name, string providerKey, string issuer) =>
        new()
        {
            Name = name,
            CanonicalIdentity = new C.CanonicalIdentity
            {
                ProviderKey = providerKey,
                SubjectClaimType = "oid",
                Issuer = issuer
            }
        };

    /// <summary>
    /// Counts tenant endpoint calls and returns the selected tenant.
    /// </summary>
    protected sealed class CountingTenantsHandler : HttpMessageHandler
    {
        int _calls;

        /// <summary>
        /// Gets the number of tenant endpoint requests.
        /// </summary>
        public int Calls => _calls;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """[{"id":"tenant-a","name":"Tenant A"}]""",
                    Encoding.UTF8,
                    "application/json")
            });
        }
    }
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;
using Cratis.AuthProxy.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

public class when_resolving_with_a_canonical_principal : Specification
{
    IdentityDetailsResolver _detailsResolver;
    DefaultHttpContext _context;
    CapturingHandler _handler;
    ClientPrincipal _principal;

    void Establish()
    {
        var configuration = new C.AuthProxy
        {
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
            },
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "http://backend/" } }
            }
        };
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(configuration);
        var authenticationOptions = Substitute.For<IOptionsMonitor<C.Authentication>>();
        authenticationOptions.CurrentValue.Returns(configuration.Authentication);
        var canonicalResolver = new CanonicalIdentityResolver(authenticationOptions);
        var services = new ServiceCollection()
            .AddSingleton<ICanonicalIdentityResolver>(canonicalResolver)
            .BuildServiceProvider();
        _context = new DefaultHttpContext
        {
            RequestServices = services,
            User = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("oid", "configured-subject"),
                new Claim("sub", "old-sub")
            ],
            "github"))
        };
        _principal = _context.BuildClientPrincipal()!;

        _handler = new CapturingHandler();
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(new HttpClient(_handler));
        _detailsResolver = new IdentityDetailsResolver(
            options,
            clients,
            [],
            new MemoryCache(new MemoryCacheOptions()),
            Substitute.For<IIdentityAuthorizationCache>(),
            Substitute.For<ILogger<IdentityDetailsResolver>>());
    }

    async Task Because() => await _detailsResolver.Resolve(_context, _principal, "tenant");

    [Fact] void should_forward_the_same_subject_in_the_principal_id_header() => _handler.Request!.Headers.GetValues(Headers.PrincipalId).Single().ShouldEqual("configured-subject");
    [Fact] void should_forward_the_same_reserved_tuple_in_the_client_principal() => Encoding.UTF8.GetString(Convert.FromBase64String(_handler.Request!.Headers.GetValues(Headers.Principal).Single())).ShouldContain("urn:cratis:identity:provider-key");

    sealed class CapturingHandler : HttpMessageHandler
    {
        public HttpRequestMessage? Request { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") });
        }
    }
}

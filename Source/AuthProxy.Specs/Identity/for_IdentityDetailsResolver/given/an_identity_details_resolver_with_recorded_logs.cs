// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Authentication;
using Cratis.AuthProxy.given;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver.given;

/// <summary>
/// Provides an identity details resolver whose enabled logger records every formatted message.
/// </summary>
public class an_identity_details_resolver_with_recorded_logs : Specification
{
    protected const string ProviderKey = "sensitive-provider-key";
    protected const string Issuer = "https://sensitive-issuer.example.com";
    protected const string Subject = "sensitive-canonical-subject";
    protected const string TenantId = "tenant-a";
    protected const string SensitiveResponseBody = "sensitive-downstream-response-body";

    protected RecordingLogger<IdentityDetailsResolver> _logger;

    protected IdentityDetailsResolver CreateResolver(HttpStatusCode statusCode = HttpStatusCode.OK, string body = "{}")
    {
        _logger = new RecordingLogger<IdentityDetailsResolver>();
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(new HttpClient(new IdentityResponseHandler(statusCode, body)));
        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configuration.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" } }
            }
        });
        return new IdentityDetailsResolver(
            configuration,
            clients,
            [],
            new MemoryCache(new MemoryCacheOptions()),
            Substitute.For<IIdentityAuthorizationCache>(),
            _logger);
    }

    protected static ClientPrincipal CanonicalPrincipal(IEnumerable<ClientPrincipalClaim>? claims = null) =>
        new()
        {
            IdentityProvider = ProviderKey,
            UserId = Subject,
            Claims = claims ??
            [
                Claim(CanonicalIdentityClaims.ProviderKey, ProviderKey),
                Claim(CanonicalIdentityClaims.Issuer, Issuer),
                Claim(CanonicalIdentityClaims.Subject, Subject)
            ]
        };

    protected static ClientPrincipalClaim Claim(string type, string value) => new() { Type = type, Value = value };

    protected void ShouldNotContainCanonicalIdentity()
    {
        _logger.Text.ShouldNotContain(ProviderKey);
        _logger.Text.ShouldNotContain(Issuer);
        _logger.Text.ShouldNotContain(Subject);
    }

    /// <summary>
    /// Returns a configured identity endpoint response.
    /// </summary>
    /// <param name="statusCode">The status code returned by the identity endpoint.</param>
    /// <param name="body">The response body returned by the identity endpoint.</param>
    sealed class IdentityResponseHandler(HttpStatusCode statusCode, string body) : HttpMessageHandler
    {
        /// <summary>
        /// Sends the identity endpoint request and returns the configured response.
        /// </summary>
        /// <param name="request">The identity endpoint request.</param>
        /// <param name="cancellationToken">The token used to cancel the request.</param>
        /// <returns>The configured identity endpoint response.</returns>
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(statusCode) { Content = new StringContent(body) });
    }
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text.Json;
using Cratis.AuthProxy.Invites;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.Scenarios.when_invitation_link_is_used;

public class MetadataAuthProxyFactory : AuthProxyFactory
{
    public const string MetadataUrl = "https://lobby.example.com/.well-known/ante/invitation-token";
    public const string Issuer = "urn:cratis:ante:store:namespace";
    public const string Audience = "urn:cratis:ante:store:namespace:lobby";

    public bool MetadataUnavailable { get; set; }

    public MetadataAuthProxyFactory() => InviteKeyPair.PrivateKey.KeyId = "known";

    protected override IEnumerable<KeyValuePair<string, string?>> GetAdditionalConfiguration() => new Dictionary<string, string?>
    {
        [$"{C.AuthProxy.SectionKey}:Invite:PublicKeyPem"] = string.Empty,
        [$"{C.AuthProxy.SectionKey}:Invite:TokenMetadataUrl"] = MetadataUrl,
        [$"{C.AuthProxy.SectionKey}:Invite:Issuer"] = Issuer,
        [$"{C.AuthProxy.SectionKey}:Invite:Audience"] = Audience
    };

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(services =>
        {
            var existing = (IHttpClientFactory)services.Last(service => service.ServiceType == typeof(IHttpClientFactory)).ImplementationInstance!;
            services.AddSingleton<IHttpClientFactory>(new MetadataClientFactory(this, existing));
        });
    }

    sealed class MetadataClientFactory(MetadataAuthProxyFactory owner, IHttpClientFactory otherClients) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => name == InvitationTokenKeys.HttpClientName
            ? new HttpClient(new MetadataHandler(owner))
            : otherClients.CreateClient(name);
    }

    sealed class MetadataHandler(MetadataAuthProxyFactory owner) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (owner.MetadataUnavailable)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            }
            var parameters = owner.InviteKeyPair.PrivateKey.Rsa.ExportParameters(false);
            var body = request.RequestUri!.AbsoluteUri == MetadataUrl
                ? JsonSerializer.Serialize(new { issuer = Issuer, audience = Audience, jwks_uri = "https://lobby.example.com/.well-known/ante/jwks.json", token_signing_alg_values_supported = new[] { "RS256" } })
                : JsonSerializer.Serialize(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = "known", n = Base64UrlEncoder.Encode(parameters.Modulus), e = Base64UrlEncoder.Encode(parameters.Exponent) } } });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        }
    }
}

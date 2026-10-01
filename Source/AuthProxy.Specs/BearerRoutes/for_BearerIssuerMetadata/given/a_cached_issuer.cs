// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerIssuerMetadata.given;

public class a_cached_issuer : Specification
{
    protected readonly ResolvedBearerIssuer Issuer = new("https://issuer.example.test/", "https://issuer.example.test/metadata", ["at+jwt"], true);
    protected readonly MetadataHandler Handler = new();
    protected readonly MetadataClock Clock = new();
    protected BearerIssuerMetadata Metadata;
    HttpClient _client;

    async Task Establish()
    {
        _client = new HttpClient(Handler);
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_client);
        Metadata = new BearerIssuerMetadata(factory, NullLogger<BearerIssuerMetadata>.Instance, Clock);
        await Metadata.GetSigningKeys(Issuer, CancellationToken.None);
    }

    void Destroy()
    {
        Handler.Release.TrySetResult();
        Metadata.Dispose();
        _client.Dispose();
    }

    protected class MetadataClock : TimeProvider
    {
        DateTimeOffset _now = DateTimeOffset.UtcNow;

        public override DateTimeOffset GetUtcNow() => _now;
        internal void Advance(TimeSpan interval) => _now += interval;
    }

    protected class MetadataHandler : HttpMessageHandler
    {
        readonly string _modulus;
        readonly string _exponent;

        internal MetadataHandler()
        {
            using var rsa = RSA.Create(2048);
            var parameters = rsa.ExportParameters(false);
            _modulus = Base64UrlEncoder.Encode(parameters.Modulus);
            _exponent = Base64UrlEncoder.Encode(parameters.Exponent);
        }

        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Unavailable { get; set; }
        internal bool Delay { get; set; }
        internal int Requests { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath == "/metadata")
            {
                Requests++;
                if (Delay)
                {
                    Started.TrySetResult();
                    await Release.Task.WaitAsync(cancellationToken);
                }

                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(new
                    {
                        issuer = Unavailable ? "https://another-issuer.example.test/" : "https://issuer.example.test/",
                        jwks_uri = "https://issuer.example.test/keys",
                    })),
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    keys = new[] { new { kty = "RSA", use = "sig", kid = Requests == 1 ? "known" : "rotated", n = _modulus, e = _exponent } },
                })),
            };
        }
    }
}

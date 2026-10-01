// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace Cratis.AuthProxy.BearerRoutes.for_BearerIssuerMetadata;

public class when_initial_metadata_retrieval_fails : Specification
{
    readonly ResolvedBearerIssuer _issuer = new("https://issuer.example.test/", "https://issuer.example.test/metadata", ["at+jwt"], true);
    readonly FailingMetadataHandler _handler = new();
    HttpClient _client;
    BearerIssuerMetadata _metadata;
    IReadOnlyCollection<SecurityKey>?[] _results;

    void Establish()
    {
        _client = new HttpClient(_handler);
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_client);
        _metadata = new BearerIssuerMetadata(factory, NullLogger<BearerIssuerMetadata>.Instance);
    }

    async Task Because()
    {
        var first = _metadata.GetSigningKeys(_issuer, CancellationToken.None);
        await _handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var waiting = Enumerable.Range(0, 8).Select(_ => _metadata.GetSigningKeys(_issuer, CancellationToken.None)).ToArray();
        _handler.Complete.SetResult();
        _results = await Task.WhenAll(waiting.Prepend(first));
        _metadata.RequestRefresh(_issuer);
        await _metadata.GetSigningKeys(_issuer, CancellationToken.None);
    }

    void Destroy()
    {
        _metadata.Dispose();
        _client.Dispose();
    }

    [Fact] void should_return_unavailable_for_every_waiting_request() => _results.All(_ => _ is null).ShouldBeTrue();
    [Fact] void should_fetch_only_once_during_the_failure_backoff_even_when_refresh_is_requested() => _handler.Requests.ShouldEqual(1);

    sealed class FailingMetadataHandler : HttpMessageHandler
    {
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Complete { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Requests { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            Started.TrySetResult();
            await Complete.Task.WaitAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }
}

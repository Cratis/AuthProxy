// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using Cratis.AuthProxy.Authentication;

namespace Cratis.AuthProxy.Identity.for_IdentityDetailsResolver;

/// <summary>
/// Specifies that resolver locking does not deduplicate distinct canonical tuples sharing a raw subject.
/// </summary>
public class when_resolving_concurrent_canonical_identity_details : Specification
{
    OverlapIdentityHandler _handler;
    IdentityDetailsResolver _resolver;
    bool _requestsOverlapped;

    void Establish()
    {
        _handler = new OverlapIdentityHandler();
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(_handler, disposeHandler: false));
        var configuration = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        configuration.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["main"] = new() { Backend = new C.ServiceEndpoint { BaseUrl = "https://backend.example.com" } }
            }
        });
        _resolver = new IdentityDetailsResolver(
            configuration,
            clients,
            [],
            new MemoryCache(new MemoryCacheOptions()),
            Substitute.For<IIdentityAuthorizationCache>(),
            Substitute.For<ILogger<IdentityDetailsResolver>>());
    }

    async Task Because()
    {
        var first = _resolver.Resolve(new DefaultHttpContext(), Principal("workforce-a", "https://identity-a.example.com"), "tenant-a");
        await _handler.FirstRequestStarted;
        var second = _resolver.Resolve(new DefaultHttpContext(), Principal("workforce-b", "https://identity-b.example.com"), "tenant-a");
        await Task.WhenAll(first, second);
        _requestsOverlapped = _handler.RequestsOverlapped;
    }

    [Fact] void should_use_independent_resolver_locks() => _requestsOverlapped.ShouldBeTrue();
    [Fact] void should_call_the_identity_endpoint_for_each_tuple() => _handler.Calls.ShouldEqual(2);

    static ClientPrincipal Principal(string providerKey, string issuer) =>
        new()
        {
            IdentityProvider = providerKey,
            UserId = "shared-subject",
            Claims =
            [
                new() { Type = CanonicalIdentityClaims.ProviderKey, Value = providerKey },
                new() { Type = CanonicalIdentityClaims.Issuer, Value = issuer },
                new() { Type = CanonicalIdentityClaims.Subject, Value = "shared-subject" }
            ]
        };

    /// <summary>
    /// Detects whether a second endpoint request starts while the first request is still active.
    /// </summary>
    sealed class OverlapIdentityHandler : HttpMessageHandler
    {
        readonly TaskCompletionSource _firstRequestStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        readonly TaskCompletionSource _secondRequestStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        int _calls;

        /// <summary>
        /// Gets a task that completes when the first endpoint request starts.
        /// </summary>
        public Task FirstRequestStarted => _firstRequestStarted.Task;

        /// <summary>
        /// Gets the number of endpoint requests.
        /// </summary>
        public int Calls => _calls;

        /// <summary>
        /// Gets a value indicating whether the second request started before the first completed.
        /// </summary>
        public bool RequestsOverlapped { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _calls);
            if (call == 1)
            {
                _firstRequestStarted.SetResult();
                var completed = await Task.WhenAny(_secondRequestStarted.Task, Task.Delay(TimeSpan.FromSeconds(1), cancellationToken));
                RequestsOverlapped = completed == _secondRequestStarted.Task;
            }
            else
            {
                _secondRequestStarted.TrySetResult();
            }

            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
        }
    }
}

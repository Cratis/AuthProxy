// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity;
using Cratis.AuthProxy.Identity;
using Cratis.AuthProxy.SignInCallbacks;
using Cratis.Specifications;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace Cratis.AuthProxy.Security.for_ForwardedIdentitySigning;

public class when_a_sign_in_callback_is_retried : Specification
{
    readonly byte[] _key = Enumerable.Repeat((byte)42, 32).ToArray();
    CallbackReceiver _receiver;
    SignInCallbackSender _sender;
    SignInCallbackRequest _request;
    bool _first;
    bool _second;

    void Establish()
    {
        var config = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        config.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new()
                {
                    Backend = new() { BaseUrl = "https://app.example/base" },
                    ForwardedIdentity = new() { Audience = "callback-backend", KeyId = "callback-1", SecretBase64 = Convert.ToBase64String(_key) }
                }
            }
        });
        var signer = new ForwardedIdentitySigner(config, TimeProvider.System, NullLogger<ForwardedIdentitySigner>.Instance);
        _receiver = new(_key);
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(ForwardedIdentityServiceCollectionExtensions.HttpClientName).Returns(_ => new HttpClient(_receiver, false));
        _sender = new(factory, signer, config, NullLogger<SignInCallbackSender>.Instance);
        _request = new("app", "https://app.example/base/.cratis/auth/sign-in", TimeSpan.FromSeconds(2), string.Empty, SignInCallbackKind.SignedIn, new ClientPrincipal { IdentityProvider = "spec", UserId = "spec-user", UserDetails = "Spec User" }, "spec-tenant", DateTimeOffset.UtcNow);
    }

    async Task Because()
    {
        _first = await _sender.Send(_request, CancellationToken.None);
        _second = await _sender.Send(_request, CancellationToken.None);
    }

    [Fact] void should_observe_the_first_failure() => _first.ShouldBeFalse();
    [Fact] void should_deliver_the_retry() => _second.ShouldBeTrue();
    [Fact] void should_verify_both_proofs_independently() => _receiver.Received.TrueForAll(observation => observation.Verified).ShouldBeTrue();
    [Fact] void should_sign_each_attempt() => _receiver.Received.Count.ShouldEqual(2);
    [Fact] void should_issue_a_fresh_nonce() => _receiver.Received[0].Proof.Split('.')[3].ShouldNotEqual(_receiver.Received[1].Proof.Split('.')[3]);
    [Fact] void should_keep_the_method_and_path() => _receiver.Received.TrueForAll(observation => observation.Method == "POST" && observation.RawTarget == "/base/.cratis/auth/sign-in").ShouldBeTrue();

    void Destroy() => _receiver.Dispose();

    sealed class CallbackReceiver(byte[] key) : HttpMessageHandler
    {
        internal List<ForwardedIdentityObservation> Received { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var observation = new ForwardedIdentityObservation(request.Method.Method, request.RequestUri!.PathAndQuery, request.Headers.ToDictionary(header => header.Key, header => header.Value.ToArray(), StringComparer.OrdinalIgnoreCase), false);
            Received.Add(observation with { Verified = ForwardedIdentityVerifier.Verify(observation, "callback-backend", "callback-1", key) });
            return Task.FromResult(new HttpResponseMessage(Received.Count == 1 ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.NoContent));
        }
    }
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ForwardedIdentity.for_IdentityEndpointCaller.given;

public class a_caller_answered_by_the_service : Specification
{
    protected IdentityEndpointCaller _caller;
    protected IdentityVerificationOutcome _outcome;
    protected TimeSpan _timeout = TimeSpan.Zero;

    protected virtual Task<HttpResponseMessage> Respond(CancellationToken cancellationToken) =>
        Task.FromResult(Json(HttpStatusCode.OK, "{}"));

    protected static HttpResponseMessage Json(HttpStatusCode statusCode, string body) =>
        new(statusCode) { Content = new StringContent(body) };

    void Establish()
    {
        var clients = Substitute.For<IHttpClientFactory>();
        clients.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(new RespondingHandler(Respond)));
        var signer = Substitute.For<IForwardedIdentitySigner>();
        signer.Sign(Arg.Any<HttpRequestMessage>(), Arg.Any<ForwardedIdentitySigningTarget>()).Returns(ForwardedIdentitySigningOutcome.NotConfigured);
        _caller = new(clients, Substitute.For<ILogger<IdentityEndpointCaller>>(), signer);
    }

    async Task Because() => _outcome = await Call(CancellationToken.None);

    protected Task<IdentityVerificationOutcome> Call(CancellationToken cancellationToken) =>
        _caller.Call(new("app", "https://backend.example", new() { UserId = "u" }, "tenant", "spec-caller", _timeout), cancellationToken);

    sealed class RespondingHandler(Func<CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            respond(cancellationToken);
    }
}

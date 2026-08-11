// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Admission.given;

/// <summary>
/// An <see cref="IHttpClientFactory"/> that answers every call from one delegate, with the timeout the
/// spec asks for.
/// </summary>
/// <param name="handler">What the verifier answers.</param>
/// <param name="timeout">How long the client waits. Defaults to a generous ten seconds.</param>
public sealed class StubHttpClientFactory(
    Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler,
    TimeSpan? timeout = null) : IHttpClientFactory
{
    /// <summary>
    /// Gets the number of calls the factory has answered.
    /// </summary>
    public int Calls { get; private set; }

    /// <inheritdoc/>
    public HttpClient CreateClient(string name)
    {
        Calls++;

        return new HttpClient(new DispatchingHandler(handler))
        {
            Timeout = timeout ?? TimeSpan.FromSeconds(10),
        };
    }

    sealed class DispatchingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            handler(request, cancellationToken);
    }
}

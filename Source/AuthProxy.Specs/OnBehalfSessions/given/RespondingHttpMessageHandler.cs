// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Text;

namespace Cratis.AuthProxy.OnBehalfSessions.given;

/// <summary>
/// Answers every request with a fixed status and body, and records what it was sent.
/// </summary>
/// <param name="statusCode">The status to answer with.</param>
/// <param name="body">The JSON body to answer with, if any.</param>
public class RespondingHttpMessageHandler(HttpStatusCode statusCode, string? body = null) : HttpMessageHandler
{
    public HttpRequestMessage? LastRequest { get; private set; }

    public ReadOnlyMemory<byte> LastRequestBytes { get; private set; }

    public string? LastAuthorization { get; private set; }

    public Dictionary<string, string> LastHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);

    public int Calls { get; private set; }

    public IHttpClientFactory AsFactory()
    {
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient(Arg.Any<string>()).Returns(_ => new HttpClient(this, disposeHandler: false));
        return factory;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Calls++;
        LastRequest = request;
        LastAuthorization = request.Headers.Authorization?.ToString();
        LastHeaders.Clear();
        foreach (var header in request.Headers)
        {
            LastHeaders[header.Key] = string.Join(',', header.Value);
        }

        LastRequestBytes = request.Content is null ? ReadOnlyMemory<byte>.Empty : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        var response = new HttpResponseMessage(statusCode);
        if (body is not null)
        {
            response.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        return response;
    }
}

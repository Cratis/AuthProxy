// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;
using System.Net.Http.Headers;

namespace Cratis.AuthProxy.SignIns;

public class RecordingHttpMessageHandler(HttpStatusCode statusCode = HttpStatusCode.OK) : HttpMessageHandler
{
    public HttpRequestMessage? LastRequest { get; private set; }

    public string? LastRequestBody { get; private set; }

    /// <summary>
    /// The exact bytes the transport received — the only body a digest claim can honestly be checked against.
    /// </summary>
    public ReadOnlyMemory<byte> LastRequestBytes { get; private set; }

    /// <summary>
    /// Captured while the request is still alive, since the notifier disposes it as soon as the call returns.
    /// </summary>
    public AuthenticationHeaderValue? LastRequestAuthorization { get; private set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        LastRequestAuthorization = request.Headers.Authorization;
        LastRequestBytes = request.Content is null ? default : await request.Content.ReadAsByteArrayAsync(cancellationToken);
        LastRequestBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        return new HttpResponseMessage(statusCode);
    }
}

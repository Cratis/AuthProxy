// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Links;

/// <summary>
/// Stands in for the exchange endpoint being unreachable — a DNS failure, a TLS failure, or a timeout. The
/// call leaves the process, so this is a normal operating condition rather than a bug.
/// </summary>
public class ThrowingHttpMessageHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
        throw new HttpRequestException("The link exchange endpoint could not be reached.");
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.BearerRoutes;
using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform;

/// <summary>
/// A bearer route is forwarded outside the reverse-proxy routes, so it names its service on the request itself; that
/// service wins over any reverse-proxy route the request also matched.
/// </summary>
public class when_signing_a_bearer_routed_request : a_signature_transform
{
    void Establish()
    {
        _signer.IsEnabled.Returns(true);
        _signer.Sign(Arg.Any<HttpRequestMessage>(), Arg.Any<string>()).Returns(ForwardedIdentitySigningStatus.Attested);
        RouteTo(_context.HttpContext, "frontend");
        _context.HttpContext.Items[BearerRouteDefaults.ServiceItemKey] = "mcp";
    }

    async Task Because() => await _transform.ApplyAsync(_context);

    [Fact] void should_sign_for_the_bearer_routes_service() => _signer.Received(1).Sign(_context.ProxyRequest, "mcp-audience");
}

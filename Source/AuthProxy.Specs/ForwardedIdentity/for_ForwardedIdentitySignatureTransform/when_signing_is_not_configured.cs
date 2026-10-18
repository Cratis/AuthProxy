// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform;

/// <summary>
/// An assertion a caller sent is never passed on, whether or not this deployment signs; otherwise nothing else changes.
/// </summary>
public class when_signing_is_not_configured : a_signature_transform
{
    void Establish()
    {
        _signer.IsEnabled.Returns(false);
        RouteTo(_context.HttpContext, "reports");
    }

    async Task Because() => await _transform.ApplyAsync(_context);

    [Fact] void should_strip_the_inbound_assertion() => _context.ProxyRequest.Headers.Contains(Headers.ForwardedIdentity).ShouldBeFalse();
    [Fact] void should_not_sign() => _signer.DidNotReceive().Sign(Arg.Any<HttpRequestMessage>(), Arg.Any<string>());
    [Fact] void should_leave_the_address_to_the_proxy() => _context.ProxyRequest.RequestUri.ShouldBeNull();
}

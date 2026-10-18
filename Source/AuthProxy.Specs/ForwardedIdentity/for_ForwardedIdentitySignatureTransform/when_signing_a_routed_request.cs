// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform;

/// <summary>
/// The request is signed for the service it is routed to, at the address it is actually sent to: YARP would only set
/// the address after every transform, so the transform sets it exactly as YARP would, and the signed path is the
/// rewritten one.
/// </summary>
public class when_signing_a_routed_request : a_signature_transform
{
    Uri? _signedAddress;

    void Establish()
    {
        _signer.IsEnabled.Returns(true);
        _signer.Sign(Arg.Any<HttpRequestMessage>(), Arg.Any<string>()).Returns(call =>
        {
            _signedAddress = call.Arg<HttpRequestMessage>().RequestUri;
            return ForwardedIdentitySigningStatus.Attested;
        });
        RouteTo(_context.HttpContext, "reports");
    }

    async Task Because() => await _transform.ApplyAsync(_context);

    [Fact] void should_sign_for_the_routed_service() => _signer.Received(1).Sign(_context.ProxyRequest, "reports-audience");
    [Fact] void should_sign_the_destination_address() => _signedAddress!.AbsoluteUri.ShouldEqual("https://reports.internal/base/api/items?page=2");
    [Fact] void should_strip_the_inbound_assertion_before_signing() => _context.ProxyRequest.Headers.Contains(Headers.ForwardedIdentity).ShouldBeFalse();
}

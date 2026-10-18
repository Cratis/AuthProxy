// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform.given;
using Yarp.ReverseProxy.Transforms;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentitySignatureTransform;

/// <summary>
/// A signing deployment never forwards unsigned. The transform throws, which YARP turns into a 502 before anything
/// reaches the service, both when signing fails and when the request has no service to be signed for.
/// </summary>
public class when_the_request_cannot_be_signed : a_signature_transform
{
    RequestTransformContext _unrouted;
    Exception? _failed;
    Exception? _withoutService;

    void Establish()
    {
        _signer.IsEnabled.Returns(true);
        _signer.Sign(Arg.Any<HttpRequestMessage>(), Arg.Any<string>()).Returns(ForwardedIdentitySigningStatus.Failed);
        RouteTo(_context.HttpContext, "reports");
        _unrouted = new RequestTransformContext
        {
            HttpContext = new DefaultHttpContext(),
            ProxyRequest = new HttpRequestMessage(HttpMethod.Get, "https://reports.internal/api"),
        };
    }

    async Task Because()
    {
        _failed = await Catch.Exception(async () => await _transform.ApplyAsync(_context));
        _withoutService = await Catch.Exception(async () => await _transform.ApplyAsync(_unrouted));
    }

    [Fact] void should_refuse_a_request_that_failed_to_sign() => _failed.ShouldBeOfExactType<ForwardedIdentityCouldNotBeSigned>();
    [Fact] void should_refuse_a_request_without_a_service() => _withoutService.ShouldBeOfExactType<ForwardedIdentityCouldNotBeSigned>();
    [Fact] void should_carry_no_assertion() => _context.ProxyRequest.Headers.Contains(Headers.ForwardedIdentity).ShouldBeFalse();
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SpoofableHeaders;

public class when_stripping_a_forwarded_identity_signature : Specification
{
    HeaderDictionary _headers;
    HttpRequestMessage _request;
    void Establish()
    {
        _headers = new() { ["X-Cratis-Forwarded-Identity-Signature"] = "caller-proof", ["Accept"] = "application/json" };
        _request = new();
        _request.Headers.Add("X-CRATIS-FORWARDED-IDENTITY-SIGNATURE", "caller-proof");
    }
    void Because()
    {
        SpoofableHeaders.Strip(_headers);
        SpoofableHeaders.Strip(_request.Headers);
    }
    [Fact] void should_strip_the_ingress_copy() => _headers.ContainsKey(Headers.ForwardedIdentitySignature).ShouldBeFalse();
    [Fact] void should_strip_the_proxy_copy() => _request.Headers.Contains(Headers.ForwardedIdentitySignature).ShouldBeFalse();
    [Fact] void should_preserve_uncovered_headers() => _headers.ContainsKey("Accept").ShouldBeTrue();
    void Destroy() => _request.Dispose();
}

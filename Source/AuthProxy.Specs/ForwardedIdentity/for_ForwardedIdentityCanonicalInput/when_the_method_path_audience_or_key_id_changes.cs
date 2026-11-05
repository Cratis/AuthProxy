// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardedIdentityCanonicalInput;

public class when_the_method_path_audience_or_key_id_changes : given.the_published_vector
{
    string _method;
    string _path;
    string _audience;
    string _keyId;
    void Because()
    {
        request.Method = HttpMethod.Get;
        Canonicalize();
        _method = mac;
        request.Method = HttpMethod.Post;
        request.RequestUri = new("http://backend.example/base/a/b");
        Canonicalize();
        _path = mac;
        request.RequestUri = new("http://backend.example/base/a%2fb");
        Canonicalize(audience: "other");
        _audience = mac;
        Canonicalize(keyId: "other");
        _keyId = mac;
    }
    [Fact] void should_bind_the_method() => _method.ShouldNotEqual(MacA);
    [Fact] void should_bind_the_path() => _path.ShouldNotEqual(MacA);
    [Fact] void should_refuse_a_wrong_audience() => _audience.ShouldNotEqual(MacA);
    [Fact] void should_bind_the_key_id() => _keyId.ShouldNotEqual(MacA);
}

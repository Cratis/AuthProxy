// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_SpoofableHeaders;

/// <summary>
/// The marker and the secret are AuthProxy's alone, so a browser cannot forge a callback through the proxy.
/// </summary>
public class when_stripping_sign_in_callback_headers : Specification
{
    IHeaderDictionary _headers;

    void Establish() => _headers = new HeaderDictionary
    {
        [Headers.SignInCallback] = "SignedIn",
        [Headers.SignInCallbackSecret] = "guess",
        ["x-cratis-sign-in-callback-anything"] = "x",
        ["Accept"] = "application/json"
    };

    void Because() => SpoofableHeaders.Strip(_headers);

    [Fact] void should_remove_the_marker() => _headers.ContainsKey(Headers.SignInCallback).ShouldBeFalse();
    [Fact] void should_remove_the_secret() => _headers.ContainsKey(Headers.SignInCallbackSecret).ShouldBeFalse();
    [Fact] void should_remove_anything_under_the_prefix() => _headers.ContainsKey("x-cratis-sign-in-callback-anything").ShouldBeFalse();
    [Fact] void should_keep_unrelated_headers() => _headers.ContainsKey("Accept").ShouldBeTrue();
}

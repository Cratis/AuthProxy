// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Cratis.AuthProxy.ReverseProxy.for_CallerAuthorizationHeaderTransform;

/// <summary>
/// A bearer token AuthProxy authenticated is forwarded.
/// </summary>
public class when_the_caller_authenticated_with_a_bearer_token : given.a_proxied_request
{
    void Establish() => _scheme = JwtBearerDefaults.AuthenticationScheme;

    Task Because() => Apply();

    [Fact] void should_keep_the_header() => HeaderForwarded.ShouldBeTrue();
}

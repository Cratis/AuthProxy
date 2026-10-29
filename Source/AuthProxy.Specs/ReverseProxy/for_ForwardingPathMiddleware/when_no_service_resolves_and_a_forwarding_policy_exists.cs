// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathMiddleware;

public class when_no_service_resolves_and_a_forwarding_policy_exists : given.a_forwarding_request
{
    [Fact]
    async Task should_fail_closed()
    {
        Select("missing-backend-cluster");
        await Invoke();
        AssertDenied();
    }

    [Fact]
    async Task should_preserve_the_unconfigured_pipeline()
    {
        _config.Services["app"] = new C.Service();
        Select("missing-backend-cluster");
        await Invoke();
        _continued.ShouldBeTrue();
    }
}

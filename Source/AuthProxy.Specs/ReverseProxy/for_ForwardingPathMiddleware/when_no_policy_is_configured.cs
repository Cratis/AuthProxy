// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_ForwardingPathMiddleware;

public class when_no_policy_is_configured : given.a_forwarding_request
{
    void Establish() => _config.Services["app"] = new C.Service();

    [Theory]
    [InlineData("app-backend-cluster")]
    [InlineData("missing-backend-cluster")]
    public async Task should_preserve_the_unconfigured_pipeline(string cluster)
    {
        Select(cluster);
        await Invoke();
        _continued.ShouldBeTrue();
    }
}

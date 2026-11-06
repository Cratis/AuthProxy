// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.OnBehalfSessions.for_OnBehalfApplication;

public class when_resolving_a_leading_slash_path : Specification
{
    Uri _address;
    bool _resolved;

    void Because() => _resolved = OnBehalfApplication.TryResolve(
        new()
        {
            Services = new Dictionary<string, C.Service> { ["app"] = new() { Backend = new() { BaseUrl = "https://backend.example/base/" } } },
            OnBehalf = new() { Service = "app" }
        },
        "/.cratis/on-behalf/grants",
        out _address);

    [Fact] void should_not_resolve_a_file_uri() => _address.IsFile.ShouldBeFalse();
    [Fact] void should_resolve_the_application() => _resolved.ShouldBeTrue();
    [Fact] void should_keep_the_https_backend_and_path() => _address.AbsoluteUri.ShouldEqual("https://backend.example/base/.cratis/on-behalf/grants");
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_ClientCredentialsServiceResolver;

public class when_the_default_verification_path_has_an_https_backend : Specification
{
    ClientCredentialsServiceResolver _resolver;
    ConfiguredClientCredentialsService _service;
    bool _resolved;

    void Establish()
    {
        var options = Substitute.For<IOptionsMonitor<C.AuthProxy>>();
        options.CurrentValue.Returns(new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["app"] = new() { Backend = new() { BaseUrl = "https://backend.example/base/" }, ClientCredentials = new() }
            }
        });
        _resolver = new(options, Substitute.For<ILogger<ClientCredentialsServiceResolver>>());
    }

    void Because() => _resolved = _resolver.TryResolveForTokenRequest("app", out _service, out _);

    [Fact] void should_resolve_the_service() => _resolved.ShouldBeTrue();
    [Fact] void should_resolve_the_default_path_on_the_https_origin() => _service.VerificationUri.AbsoluteUri.ShouldEqual("https://backend.example/.cratis/client-credentials/verify");
    [Fact] void should_not_resolve_a_file_uri() => _service.VerificationUri.IsFile.ShouldBeFalse();
}

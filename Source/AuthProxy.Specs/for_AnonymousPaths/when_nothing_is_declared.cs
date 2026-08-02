// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.for_AnonymousPaths;

/// <summary>
/// A configuration that declares no anonymous paths must behave exactly as it did before the feature
/// existed — nothing anonymous, for any path.
/// <para>
/// This is the compatibility guarantee every existing consumer depends on, so it is pinned rather than
/// argued: it is the one property that must hold for a deployment that never opts in.
/// </para>
/// </summary>
public class when_nothing_is_declared : Specification
{
    C.AuthProxy _emptyConfiguration;
    C.AuthProxy _configurationWithServices;

    void Establish()
    {
        _emptyConfiguration = new C.AuthProxy();
        _configurationWithServices = new C.AuthProxy
        {
            Services = new Dictionary<string, C.Service>
            {
                ["test"] = new()
                {
                    Backend = new C.ServiceEndpoint { BaseUrl = "http://backend.test/" },
                    Frontend = new C.ServiceEndpoint { BaseUrl = "http://frontend.test/" },
                },
            },
        };
    }

    [Fact] void should_resolve_no_paths_without_services() => AnonymousPaths.All(_emptyConfiguration).ShouldBeEmpty();
    [Fact] void should_resolve_no_paths_with_services() => AnonymousPaths.All(_configurationWithServices).ShouldBeEmpty();
    [Fact] void should_not_match_the_root_path() => AnonymousPaths.Matches("/", _configurationWithServices).ShouldBeFalse();
    [Fact] void should_not_match_an_application_path() => AnonymousPaths.Matches("/dashboard", _configurationWithServices).ShouldBeFalse();
    [Fact] void should_not_match_an_api_path() => AnonymousPaths.Matches("/api/anything", _configurationWithServices).ShouldBeFalse();
}

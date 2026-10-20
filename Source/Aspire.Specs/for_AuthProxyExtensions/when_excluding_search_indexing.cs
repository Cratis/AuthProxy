// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions;

public class when_excluding_search_indexing : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithSearchIndexExclusion();

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_enable_search_index_exclusion() => _environment["Cratis__AuthProxy__SearchIndexing__Exclude"].ShouldEqual(bool.TrueString);
    [Fact] void should_leave_services_unchanged() => _environment.Keys.Any(_ => _.Contains("__Services__", StringComparison.Ordinal)).ShouldBeFalse();
}

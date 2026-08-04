// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_declaring_anonymous_paths;

/// <summary>
/// Declared paths reach the proxy as the indexed environment variables its configuration binds.
/// <para>
/// The key shape is the contract between the app host and the proxy — a double-underscore path down to an
/// index — and it is what binds to the anonymous-path list on the named service. A wrong prefix, a wrong
/// separator or a wrong index silently produces a proxy that declares nothing, and the first sign of it is
/// an anonymous caller being sent to a login page.
/// </para>
/// </summary>
public class and_they_are_declared_in_one_call : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithAnonymousPaths("main", "/portal", "/api/webhooks/payments");

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_write_the_first_path_at_the_first_index() => _environment["Cratis__AuthProxy__Services__main__AnonymousPaths__0"].ShouldEqual("/portal");
    [Fact] void should_write_the_second_path_at_the_next_index() => _environment["Cratis__AuthProxy__Services__main__AnonymousPaths__1"].ShouldEqual("/api/webhooks/payments");
    [Fact] void should_write_one_variable_per_declared_path() => _environment.Keys.Count(_ => _.Contains("AnonymousPaths", StringComparison.Ordinal)).ShouldEqual(2);
}

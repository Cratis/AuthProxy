// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_declaring_anonymous_paths;

/// <summary>
/// A second call appends rather than overwriting what the first one wrote.
/// <para>
/// Indices are positions in a configuration array, so a call that restarted at zero would overwrite the
/// earlier entries and silently drop them — the app host would read as though every path were declared
/// while the proxy received only the last call's. Declaring paths in more than one place is the natural
/// way to write an app host, which is what makes this worth pinning.
/// </para>
/// <para>
/// Two services are used to show the count is kept per service: <c>other</c> starts at its own zero rather
/// than continuing <c>main</c>'s numbering.
/// </para>
/// </summary>
public class and_they_are_declared_across_several_calls : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish()
    {
        _resource.WithAnonymousPaths("main", "/portal");
        _resource.WithAnonymousPaths("main", "/api/webhooks/payments", "/status");
        _resource.WithAnonymousPaths("other", "/public");
    }

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_keep_the_path_from_the_first_call() => _environment["Cratis__AuthProxy__Services__main__AnonymousPaths__0"].ShouldEqual("/portal");
    [Fact] void should_append_the_second_call_after_it() => _environment["Cratis__AuthProxy__Services__main__AnonymousPaths__1"].ShouldEqual("/api/webhooks/payments");
    [Fact] void should_continue_appending_within_the_second_call() => _environment["Cratis__AuthProxy__Services__main__AnonymousPaths__2"].ShouldEqual("/status");
    [Fact] void should_number_each_service_independently() => _environment["Cratis__AuthProxy__Services__other__AnonymousPaths__0"].ShouldEqual("/public");
    [Fact] void should_write_one_variable_per_declared_path() => _environment.Keys.Count(_ => _.Contains("AnonymousPaths", StringComparison.Ordinal)).ShouldEqual(4);
}

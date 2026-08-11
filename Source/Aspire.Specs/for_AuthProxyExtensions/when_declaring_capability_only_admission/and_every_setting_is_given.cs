// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_declaring_capability_only_admission;

/// <summary>
/// Every setting a deployment overrides reaches the proxy in the form its configuration binder reads —
/// notably the lifetime, which binds as a <see cref="TimeSpan"/> and therefore has to be written in the
/// invariant <c>hh:mm:ss</c> form rather than in whatever the host's culture would produce.
/// </summary>
public class and_every_setting_is_given : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithCapabilityOnlyAdmission(
        "https://members.example.com/admit",
        "/enter",
        512,
        TimeSpan.FromMinutes(3));

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_declare_the_presentation_path() => _environment["Cratis__AuthProxy__Admission__Capability__Path"].ShouldEqual("/enter");
    [Fact] void should_declare_the_capability_bound() => _environment["Cratis__AuthProxy__Admission__Capability__MaximumLength"].ShouldEqual("512");
    [Fact] void should_declare_the_entry_lifetime() => _environment["Cratis__AuthProxy__Admission__EntryLifetime"].ShouldEqual("00:03:00");
}

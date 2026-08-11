// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_declaring_capability_only_admission;

/// <summary>
/// Closing the interactive contract is its own builder rather than another optional argument on
/// <c>AddAuthProxy</c>, and naming only the verifier writes every key the proxy reads — with the same
/// defaults the proxy itself would have used.
/// <para>
/// The Aspire package cannot reference the proxy it configures, so these strings are the only thing joining
/// the two. A rename on either side binds nothing and falls back to a default — which for the mode means
/// the door silently stays open, and for the verifier means a deployment that refuses every caller alive.
/// </para>
/// </summary>
public class and_only_the_verifier_is_given : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithCapabilityOnlyAdmission("https://members.example.com/admit");

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_close_the_interactive_contract() => _environment["Cratis__AuthProxy__Admission__Mode"].ShouldEqual("CapabilityOnly");
    [Fact] void should_declare_the_verifier() => _environment["Cratis__AuthProxy__Admission__Capability__VerifierUrl"].ShouldEqual("https://members.example.com/admit");
    [Fact] void should_default_the_presentation_path() => _environment["Cratis__AuthProxy__Admission__Capability__Path"].ShouldEqual("/.cratis/admission");
    [Fact] void should_default_the_capability_bound() => _environment["Cratis__AuthProxy__Admission__Capability__MaximumLength"].ShouldEqual("4096");
    [Fact] void should_default_the_entry_lifetime_to_ten_minutes() => _environment["Cratis__AuthProxy__Admission__EntryLifetime"].ShouldEqual("00:10:00");
    [Fact] void should_leave_the_invite_section_alone() => _environment.Keys.Any(_ => _.Contains("__Invite", StringComparison.Ordinal)).ShouldBeFalse();
    [Fact] void should_leave_the_services_alone() => _environment.Keys.Any(_ => _.Contains("__Services__", StringComparison.Ordinal)).ShouldBeFalse();
}

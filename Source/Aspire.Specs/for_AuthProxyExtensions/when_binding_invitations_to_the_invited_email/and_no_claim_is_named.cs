// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Aspire.for_AuthProxyExtensions.when_binding_invitations_to_the_invited_email;

/// <summary>
/// An empty claim has to write nothing at all, rather than write the key empty.
/// <para>
/// The two are not the same to a deployment: an absent key lets any lower-precedence configuration source —
/// an appsettings file, a Helm value, a container default — still name a claim, while an emitted empty value
/// silently overrides all of them and switches recipient binding off. Retaining the released default means
/// staying out of the section entirely.
/// </para>
/// </summary>
public class and_no_claim_is_named : given.an_auth_proxy_resource
{
    Dictionary<string, string> _environment;

    void Establish() => _resource.WithInviteEmailBinding(string.Empty);

    async Task Because() => _environment = await EnvironmentVariables();

    [Fact] void should_not_write_the_binding_at_all() => _environment.ContainsKey("Cratis__AuthProxy__Invite__EmailClaim").ShouldBeFalse();
}

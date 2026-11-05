// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsMaterialSource;

public class when_replacing_mounted_files : given.a_tls_policy
{
    string _first;
    string _second;
    bool _changed;
    void Establish() => _first = source.Current.ClientCertificate!.Thumbprint;
    void Because()
    {
        using var replacement = certificates.Issue(client: true);
        _second = replacement.Thumbprint;
        certificates.WriteClient(replacement);
        _changed = source.TryReload();
    }
    [Fact] void should_publish_a_new_snapshot() => _changed.ShouldBeTrue();
    [Fact] void should_change_the_handshake_identity() => policy.SelectClientCertificate("localhost")!.Thumbprint.ShouldEqual(_second);
    [Fact] void should_not_keep_the_previous_identity() => source.Current.ClientCertificate!.Thumbprint.ShouldNotEqual(_first);
    [Fact] void should_not_publish_unchanged_bytes() => source.TryReload().ShouldBeFalse();
}

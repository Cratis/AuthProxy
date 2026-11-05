// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsMaterialSource;

public class when_a_replacement_is_invalid : given.a_tls_policy
{
    string _original;
    bool _changed;
    void Establish() => _original = source.Current.Fingerprint;
    void Because()
    {
        File.WriteAllText(certificates.KeyPath, "incomplete replacement");
        _changed = source.TryReload();
    }
    [Fact] void should_refuse_the_replacement() => _changed.ShouldBeFalse();
    [Fact] void should_keep_the_last_good_material() => source.Current.Fingerprint.ShouldEqual(_original);
    [Fact] void should_still_select_the_original_identity() => policy.SelectClientCertificate("localhost")!.HasPrivateKey.ShouldBeTrue();
}

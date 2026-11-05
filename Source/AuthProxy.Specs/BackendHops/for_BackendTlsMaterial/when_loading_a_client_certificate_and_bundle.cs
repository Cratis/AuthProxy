// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.BackendHops.for_BackendTlsMaterial;

public class when_loading_a_client_certificate_and_bundle : Specification
{
    given.TestCertificates _certificates;
    BackendTlsMaterial? _material;
    bool _loaded;
    string? _problem;

    void Establish() => _certificates = new();
    void Because() => _loaded = BackendTlsMaterial.TryLoad(_certificates.Settings, DateTimeOffset.UtcNow, out _material, out _problem);
    void Destroy() => _certificates.Dispose();

    [Fact] void should_load_the_material() => _loaded.ShouldBeTrue();
    [Fact] void should_retain_the_private_key() => _material!.ClientCertificate!.HasPrivateKey.ShouldBeTrue();
    [Fact] void should_load_the_anchor() => _material!.TrustAnchors.Count.ShouldEqual(1);
    [Fact] void should_have_no_problem() => _problem.ShouldBeNull();
}

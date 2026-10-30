// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaAddresses;

public class when_dns_answers_with_pod_addresses : Specification
{
    IReadOnlyList<Uri> _result;

    void Because() => _result = ReplicaAddresses.From(
        new Uri("https://core:8443/base/"),
        [IPAddress.Parse("fd00::2"), IPAddress.Parse("10.0.0.9"), IPAddress.Parse("10.0.0.2"), IPAddress.Parse("10.0.0.9")]);

    [Fact] void should_keep_scheme_port_and_path() => _result.All(_ => _.Scheme == "https" && _.Port == 8443 && _.AbsolutePath == "/base/").ShouldBeTrue();
    [Fact] void should_order_by_family_then_address_and_remove_duplicates() => _result.Select(_ => _.Host).ShouldEqual(["10.0.0.2", "10.0.0.9", "[fd00::2]"]);
}

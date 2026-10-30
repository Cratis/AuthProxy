// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaAddresses;

public class when_dns_answers_with_special_purpose_addresses : Specification
{
    IReadOnlyList<Uri> _result;

    void Because() => _result = ReplicaAddresses.From(
        new Uri("http://core:8080/"),
        new[]
        {
            "127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "::", "0.1.2.3", "169.254.169.254", "fe80::1",
            "224.0.0.1", "ff02::1", "240.0.0.1", "255.255.255.255",
        }.Select(IPAddress.Parse).Append(IPAddress.Parse("10.1.1.1")));

    [Fact] void should_keep_only_the_pod_address() => _result.Select(_ => _.Host).ShouldEqual(["10.1.1.1"]);
}

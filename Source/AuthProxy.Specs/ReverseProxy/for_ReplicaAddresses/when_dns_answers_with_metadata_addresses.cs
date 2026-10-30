// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaAddresses;

public class when_dns_answers_with_metadata_addresses : Specification
{
    IReadOnlyList<Uri> _result;

    void Because() => _result = ReplicaAddresses.From(
        new Uri("http://core:8080/"),
        new[] { "fd00:ec2::254", "::ffff:169.254.169.254", "::ffff:127.0.0.1", "fd00:ec2::255" }.Select(IPAddress.Parse));

    [Fact] void should_keep_only_the_other_unique_local_address() => _result.Select(_ => _.Host).ShouldEqual(["[fd00:ec2::255]"]);
}

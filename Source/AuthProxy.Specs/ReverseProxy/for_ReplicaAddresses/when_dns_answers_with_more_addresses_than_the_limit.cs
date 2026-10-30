// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.ReverseProxy.for_ReplicaAddresses;

public class when_dns_answers_with_more_addresses_than_the_limit : Specification
{
    IReadOnlyList<Uri> _result;

    void Because() => _result = ReplicaAddresses.From(
        new Uri("http://core:8080/"),
        Enumerable.Range(1, 200).Select(i => IPAddress.Parse($"10.0.0.{i}")));

    [Fact] void should_keep_the_limit() => _result.Count.ShouldEqual(ReplicaAddresses.MaximumReplicas);
}

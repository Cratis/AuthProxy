// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net;

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyAddress;

/// <summary>
/// A range means the range, including when it was written against a host address inside it — which is how
/// every other tool an operator copies a range from reads it.
/// </summary>
public class when_resolving_a_range : Specification
{
    System.Net.IPNetwork? _result;
    System.Net.IPNetwork? _writtenWithHostBits;

    void Because()
    {
        _result = TrustedProxyAddress.Resolve("10.0.0.0/8");
        _writtenWithHostBits = TrustedProxyAddress.Resolve("10.0.0.1/8");
    }

    [Fact] void should_contain_an_address_inside_it() => _result!.Value.Contains(IPAddress.Parse("10.4.5.6")).ShouldBeTrue();
    [Fact] void should_not_contain_an_address_outside_it() => _result!.Value.Contains(IPAddress.Parse("11.4.5.6")).ShouldBeFalse();
    [Fact] void should_normalize_a_range_written_against_a_host_address() => _writtenWithHostBits.ShouldEqual(_result);
}

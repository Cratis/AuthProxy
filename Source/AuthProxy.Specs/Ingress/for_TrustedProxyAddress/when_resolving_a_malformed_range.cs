// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Ingress.for_TrustedProxyAddress;

/// <summary>
/// A range that is almost right is refused, never rounded into one that trusts more than was written.
/// </summary>
public class when_resolving_a_malformed_range
{
    [Theory]
    [InlineData("10.0.0.0/")]
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/8/8")]
    [InlineData("10.0.0.0/eight")]
    [InlineData("::1/129")]
    [InlineData("/8")]
    [InlineData("/")]
    [InlineData("10.0.0.256")]
    [InlineData("*")]
    [InlineData("any")]
    public void should_refuse_it(string entry) => TrustedProxyAddress.Resolve(entry).ShouldBeNull();
}

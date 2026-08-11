// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Extensions.Configuration;

namespace Cratis.AuthProxy.Management.for_ListenerAddresses;

/// <summary>
/// A deployment that declares no address at all still listens on one — the host's own default — and
/// re-declaring the listeners has to include it. Resolving to an empty set here would mean the management
/// listener replaced the public one instead of joining it.
/// </summary>
public class when_nothing_is_declared : Specification
{
    ListenerAddresses _addresses;

    void Because() => _addresses = ListenerAddresses.Resolve(new ConfigurationBuilder().Build());

    [Fact] void should_keep_the_host_default() => _addresses.Declared.ShouldContainOnly([ListenerAddresses.HostDefault]);
    [Fact] void should_recognize_the_default_port() => _addresses.Uses(5000).ShouldBeTrue();
}

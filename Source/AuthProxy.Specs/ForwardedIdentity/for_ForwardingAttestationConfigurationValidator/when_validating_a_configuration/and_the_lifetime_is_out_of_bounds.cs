// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.ForwardedIdentity.for_ForwardingAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The lifetime is the window a captured assertion is worth anything in, so it is bounded at both ends.
/// </summary>
public class and_the_lifetime_is_out_of_bounds : a_forwarding_attestation_configuration
{
    ValidateOptionsResult _tooLong;
    ValidateOptionsResult _tooShort;
    ValidateOptionsResult _atTheUpperBound;
    ValidateOptionsResult _atTheLowerBound;

    void Because()
    {
        _tooLong = Validate(Configuration(lifetime: TimeSpan.FromSeconds(61), signingKeys: P256Key("current")));
        _tooShort = Validate(Configuration(lifetime: TimeSpan.FromSeconds(9), signingKeys: P256Key("current")));
        _atTheUpperBound = Validate(Configuration(lifetime: TimeSpan.FromSeconds(60), signingKeys: P256Key("current")));
        _atTheLowerBound = Validate(Configuration(lifetime: TimeSpan.FromSeconds(10), signingKeys: P256Key("current")));
    }

    [Fact] void should_reject_a_longer_lifetime() => _tooLong.Succeeded.ShouldBeFalse();
    [Fact] void should_reject_an_unusably_short_lifetime() => _tooShort.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_the_upper_bound() => _atTheUpperBound.Succeeded.ShouldBeTrue();
    [Fact] void should_accept_the_lower_bound() => _atTheLowerBound.Succeeded.ShouldBeTrue();
}

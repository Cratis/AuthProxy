// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.given;

namespace Cratis.AuthProxy.SignIns.for_SignInAttestationConfigurationValidator.when_validating_a_configuration;

/// <summary>
/// The time binding is what keeps a captured envelope from being useful later, so its window is bounded at
/// both ends rather than left to a deployer to widen into meaninglessness.
/// </summary>
public class and_the_lifetime_is_out_of_bounds : a_sign_in_attestation_configuration
{
    ValidateOptionsResult _tooLong;
    ValidateOptionsResult _tooShort;
    ValidateOptionsResult _atTheUpperBound;

    void Because()
    {
        _tooLong = Validate(Configuration(lifetime: TimeSpan.FromSeconds(61), signingKeys: PrivateKey("current")));
        _tooShort = Validate(Configuration(lifetime: TimeSpan.FromSeconds(9), signingKeys: PrivateKey("current")));
        _atTheUpperBound = Validate(Configuration(lifetime: TimeSpan.FromSeconds(60), signingKeys: PrivateKey("current")));
    }

    [Fact] void should_reject_a_longer_lifetime() => _tooLong.Succeeded.ShouldBeFalse();
    [Fact] void should_reject_an_unusably_short_lifetime() => _tooShort.Succeeded.ShouldBeFalse();
    [Fact] void should_accept_the_upper_bound() => _atTheUpperBound.Succeeded.ShouldBeTrue();
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator;

public class when_the_refresh_interval_is_out_of_range : given.a_validator
{
    List<ValidateOptionsResult> _results;

    void Because() => _results =
    [
        Validate(Backend(Sticky(refresh: TimeSpan.Zero))),
        Validate(Backend(Sticky(refresh: TimeSpan.FromMilliseconds(999)))),
        Validate(Backend(Sticky(refresh: TimeSpan.FromHours(1) + TimeSpan.FromTicks(1)))),
    ];

    [Fact] void should_fail_every_one() => _results.TrueForAll(_ => _.Failed).ShouldBeTrue();
    [Fact] void should_name_the_refresh_interval_key() => _results.TrueForAll(_ => _.FailureMessage.Contains("Backend:StickyRouting:RefreshInterval")).ShouldBeTrue();
}

// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.ReverseProxy.for_StickyRoutingConfigurationValidator;

public class when_it_is_disabled : given.a_validator
{
    ValidateOptionsResult _odd;
    ValidateOptionsResult _misplaced;

    void Because()
    {
        _odd = Validate(Backend(Sticky("10.0.0.1", TimeSpan.Zero, enabled: false), name: "core api"));
        _misplaced = Validate(new()
        {
            Services = new Dictionary<string, C.Service>() { ["core"] = new() { Frontend = new() { BaseUrl = "http://core/", StickyRouting = Sticky(enabled: false) } } },
        });
    }

    [Fact] void should_not_report_the_values() => _odd.Succeeded.ShouldBeTrue();
    [Fact] void should_still_report_the_placement() => _misplaced.Failed.ShouldBeTrue();
}

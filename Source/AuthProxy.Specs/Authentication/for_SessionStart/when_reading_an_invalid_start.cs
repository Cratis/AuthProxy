// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.AspNetCore.Authentication;

namespace Cratis.AuthProxy.Authentication.for_SessionStart;

public class when_reading_an_invalid_start : Specification
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("-1")]
    [InlineData("253402300800")]
    [InlineData("not-a-time")]
    public void should_not_read_a_start(string? value) => SessionStart.TryRead(new AuthenticationProperties(new Dictionary<string, string?> { [SessionStart.PropertyKey] = value }), out _).ShouldBeFalse();
    [Fact] void should_not_read_missing_properties() => SessionStart.TryRead(null, out _).ShouldBeFalse();
    [Fact] void should_not_read_a_legacy_session() => SessionStart.TryRead(new AuthenticationProperties(), out _).ShouldBeFalse();
}

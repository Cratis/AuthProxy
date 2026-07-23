// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns.for_UserAgentParser;

public class when_parsing_an_empty_user_agent : Specification
{
    UserAgentInfo _result;

    void Because() => _result = UserAgentParser.Parse(string.Empty);

    [Fact] void should_be_unknown() => _result.ShouldEqual(UserAgentInfo.Unknown);
    [Fact] void should_have_no_browser() => _result.Browser.ShouldBeEmpty();
    [Fact] void should_have_no_operating_system() => _result.OperatingSystem.ShouldBeEmpty();
}

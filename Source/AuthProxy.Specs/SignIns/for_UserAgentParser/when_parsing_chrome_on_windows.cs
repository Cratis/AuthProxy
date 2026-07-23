// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns.for_UserAgentParser;

public class when_parsing_chrome_on_windows : Specification
{
    const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    UserAgentInfo _result;

    void Because() => _result = UserAgentParser.Parse(UserAgent);

    [Fact] void should_detect_chrome() => _result.Browser.ShouldEqual("Chrome");
    [Fact] void should_detect_windows() => _result.OperatingSystem.ShouldEqual("Windows");
    [Fact] void should_keep_the_raw_value() => _result.Raw.ShouldEqual(UserAgent);
}

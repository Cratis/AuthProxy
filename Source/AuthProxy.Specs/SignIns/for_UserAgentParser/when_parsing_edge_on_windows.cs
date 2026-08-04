// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns.for_UserAgentParser;

public class when_parsing_edge_on_windows : Specification
{
    const string UserAgent =
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";

    UserAgentInfo _result;

    void Because()
    {
        // Edge embeds the Chrome token, so the more specific "Edg" token has to win over "Chrome".
        _result = UserAgentParser.Parse(UserAgent);
    }

    [Fact] void should_detect_edge() => _result.Browser.ShouldEqual("Edge");
    [Fact] void should_detect_windows() => _result.OperatingSystem.ShouldEqual("Windows");
}

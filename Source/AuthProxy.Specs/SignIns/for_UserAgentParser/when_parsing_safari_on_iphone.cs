// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.SignIns.for_UserAgentParser;

public class when_parsing_safari_on_iphone : Specification
{
    const string UserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";

    UserAgentInfo _result;

    void Because()
    {
        // The iPhone user-agent embeds "Mac OS X", so this also proves iOS wins over macOS.
        _result = UserAgentParser.Parse(UserAgent);
    }

    [Fact] void should_detect_safari() => _result.Browser.ShouldEqual("Safari");
    [Fact] void should_detect_ios() => _result.OperatingSystem.ShouldEqual("iOS");
}

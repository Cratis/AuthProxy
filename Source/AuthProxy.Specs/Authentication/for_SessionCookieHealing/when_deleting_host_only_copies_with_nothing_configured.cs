// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing;

public class when_deleting_host_only_copies_with_nothing_configured : given.a_browser_request
{
    void Establish() => SendCookies($"{Cookie}=session");

    void Because() => SessionCookieHealing.DeleteHostOnlyCopies(_context, _session);

    [Fact] void should_delete_nothing() => SetCookies.ShouldBeEmpty();
}

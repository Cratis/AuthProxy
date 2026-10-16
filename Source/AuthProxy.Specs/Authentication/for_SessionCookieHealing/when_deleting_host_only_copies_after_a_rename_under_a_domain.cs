// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Authentication.for_SessionCookieHealing;

public class when_deleting_host_only_copies_after_a_rename_under_a_domain : given.a_browser_request
{
    const string Renamed = ".Studio.Auth";

    void Establish()
    {
        _session.CookieName = Renamed;
        _session.CookieDomain = ".example.test";
        SendCookies($"{Cookie}=session", $"{Renamed}=session");
    }

    void Because() => SessionCookieHealing.DeleteHostOnlyCopies(_context, _session);

    [Fact] void should_delete_the_host_only_default_named_cookie() => Deleted(Cookie).ShouldBeTrue();
    [Fact] void should_delete_the_host_only_copy_of_the_renamed_cookie() => Deleted(Renamed).ShouldBeTrue();
    [Fact] void should_never_name_a_domain_so_a_domain_cookie_of_that_name_survives() => SetCookies.Any(_ => _.Contains("domain=", StringComparison.OrdinalIgnoreCase)).ShouldBeFalse();
}

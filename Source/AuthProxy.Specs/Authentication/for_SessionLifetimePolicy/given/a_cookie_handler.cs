// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Cratis.AuthProxy.Authentication.for_SessionLifetimePolicy.given;

public class a_cookie_handler(IOptionsMonitor<CookieAuthenticationOptions> options, ILoggerFactory logger) : CookieAuthenticationHandler(options, logger, UrlEncoder.Default)
{
    public Task Complete() => FinishResponseAsync();
}

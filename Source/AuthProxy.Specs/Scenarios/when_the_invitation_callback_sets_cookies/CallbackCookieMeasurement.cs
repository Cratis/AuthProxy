// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Microsoft.Net.Http.Headers;

namespace Cratis.AuthProxy.Scenarios.when_the_invitation_callback_sets_cookies;

/// <summary>
/// The size of the headers a callback response carries, measured with the same formula as the Set-Cookie size warning.
/// </summary>
/// <param name="Cookies">Each Set-Cookie header's cookie name and header length.</param>
/// <param name="SetCookieTotal">The combined Set-Cookie size, as <see cref="SetCookieSizeMiddleware"/> measures it.</param>
/// <param name="HeaderBlock">The estimated size of the whole response header block.</param>
public sealed record CallbackCookieMeasurement(IReadOnlyList<(string Name, int Length)> Cookies, int SetCookieTotal, int HeaderBlock)
{
    /// <summary>The header block size that leaves room for Kestrel's own headers inside a 4k proxy buffer.</summary>
    public const int HeaderBlockBudget = 3840;

    /// <summary>
    /// Measures a response.
    /// </summary>
    /// <param name="response">The callback response.</param>
    /// <returns>The measurement.</returns>
    public static CallbackCookieMeasurement Of(HttpResponseMessage response)
    {
        var setCookies = response.Headers.TryGetValues(HeaderNames.SetCookie, out var values) ? values.ToArray() : [];
        var headers = new HeaderDictionary { [HeaderNames.SetCookie] = setCookies };
        SetCookieSizeMiddleware.TryMeasure(headers, out var total, out _);

        var cookies = setCookies
            .Select(header => (Name: header[..Math.Max(header.IndexOf('=', StringComparison.Ordinal), 0)], header.Length))
            .ToArray();

        var block = "HTTP/1.1 302 Found\r\n".Length + 2;
        foreach (var header in response.Headers.Concat(response.Content.Headers))
        {
            block += header.Value.Sum(value => header.Key.Length + 2 + value.Length + 2);
        }

        return new CallbackCookieMeasurement(cookies, total, block);
    }

    /// <summary>
    /// Writes a per-cookie table to the spec output.
    /// </summary>
    /// <param name="title">The scenario name.</param>
    public void WriteTable(string title)
    {
        var output = TestContext.Current.TestOutputHelper;
        output?.WriteLine($"== {title}: Set-Cookie total {SetCookieTotal}, header block {HeaderBlock}");
        foreach (var (name, length) in Cookies)
        {
            output?.WriteLine($"   {length,5}  {name}");
        }
    }
}

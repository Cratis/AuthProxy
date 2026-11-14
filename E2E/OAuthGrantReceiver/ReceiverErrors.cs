// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using System.Text.Json;

namespace E2E.OAuthGrantReceiver;

static class ReceiverErrors
{
    public static bool IsRejection(Exception error) => error is Rejected or FormatException or JsonException or InvalidOperationException or
        KeyNotFoundException or ArgumentException or CryptographicException or HttpRequestException;
}

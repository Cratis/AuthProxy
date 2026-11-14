// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace E2E.OAuthGrantReceiver;

// In-process hostile-test faults only. No HTTP or configuration switch selects these.
enum DisabledCheck
{
    None,
    Signature,
    BearerBinding,
    Replay,
    Envelope,
    DuplicateHeader,
    UnknownHeader
}

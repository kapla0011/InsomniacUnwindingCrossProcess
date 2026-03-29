rule BeaconSignature
{
    meta:
        description = "Detects DEADBEEF signature bytes in beacon sections"
        author = "kapla"
        date = "2026-03-29"

    strings:
        $deadbeef = { DE AD BE EF }

    condition:
        $deadbeef
}
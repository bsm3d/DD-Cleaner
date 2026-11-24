// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Table of name pairs with their expected similarity ratio, used by the malware hunt tests on look-alike names.

    {L"svchost.exe", L"svch0st.exe", 0.909090909090909},
    {L"svchost.exe", L"svchost.exe", 1.000000000000000},
    {L"explorer.exe", L"explorer.exe", 1.000000000000000},
    {L"explorer.exe", L"explorer32.exe", 0.923076923076923},
    {L"taskhostw.exe", L"taskhostx.exe", 0.923076923076923},
    {L"abc", L"xyz", 0.000000000000000},
    {L"", L"abc", 0.000000000000000},
    {L"runtimebroker.exe", L"runtimebroker.exe", 1.000000000000000},
    {L"searchindexer.exe", L"searchlndexer.exe", 0.941176470588235},
    {L"fontdrvhost.exe", L"fontdrvhots.exe", 0.933333333333333},
    {L"conhost.exe", L"c0nhost.exe", 0.909090909090909},
    {L"dllhost.exe", L"dllhosts.exe", 0.956521739130435},
    {L"a", L"a", 1.000000000000000},
    {L"abcdefghij", L"abcxefghij", 0.900000000000000},
    {L"lsass.exe", L"lsasss.exe", 0.947368421052632},

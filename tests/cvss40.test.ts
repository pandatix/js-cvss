import { CVSS40 } from '../src/cvss40';

describe('CVSS v4.0 Section 7 test cases', () => {
    type TestCase = {
        name: string
        vector: string
    }
    describe('valid', () => {
        const testCases: TestCase[] = [
            {
                name: 'specification-example-B',
                vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
            },
            {
                name: 'specification-example-BT',
                vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:A',
            },
            // Following test cases are expected to increase the code coverage naturally.
            // They were added to the official specification Section 7.
            // => valid vectors
            {
                name: 'CVSS-BT',
                vector: 'CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P',
            },
            {
                name: 'CVSS-BE',
                vector: 'CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H',
            },
            {
                name: 'CVSS-B with Supplemental',
                vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red',
            },
            {
                // Changed IR:X and MVC:X for the test purpose
                name: 'CVSS-BTE with Supplemental',
                vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:H/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:H/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green',
            },
        ]

        testCases.forEach((testCase) => {
            test(testCase.name, () => {
                expect(new CVSS40(testCase.vector))
            })
        })
    })

    describe('invalid', () => {
        const testCases: TestCase[] = [
            {
                name: 'AV has no valid value F',
                vector: 'CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N',
            },
            {
                name: 'E defined more than once',
                vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/E:X',
            },
            {
                name: 'ui is not a valid metric abbreviation',
                vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/ui:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N',
            },
            {
                name: 'CVSS v4.0 prefix is missing',
                vector: 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N',
            },
            {
                name: 'mandatory VA is missing',
                vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/SC:N/SI:N/SA:N',
            },
            {
                name: 'fixed ordering is not respected, CVSS-BTE with Supplemental',
                vector: 'CVSS:4.0/AC:L/AV:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/CR:L/IR:X/AR:L/RE:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/AT:N/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/E:U/S:N/AU:N/R:I/V:C/U:Green',
            },
        ]

        testCases.forEach((testCase) => {
            test(testCase.name, () => {
                expect(() => {
                    new CVSS40(testCase.vector)
                }).toThrow();
            })
        })
    })
});

test('CVSS v4.0 vector', () => {
    // This test ensures it produces metrics in the proper order as defined in CVSS v4.0
    // specification Table 23, and it does not export undefined/X (Not Defined) metrics.
    const input = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green';
    var vec = new CVSS40(input);
    expect(vec.Vector()).toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green');
});

test('Setter', () => {
    var vec = new CVSS40();
    expect(() => {
        vec.Set('SA', 'H');
    });
    expect(() => {
        vec.Set('invalid', 'invalid');
    }).toThrow();
    expect(() => {
        vec.Set('SA', 'invalid');
    }).toThrow();
});

describe('Score', () => {
    type TestCase = {
        name: string
        vector: string
        score: number
        nomenclature: string
    };
    const testCases: TestCase[] = [
        {
            name: 'full-impact',
            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
            score: 10.0,
            nomenclature: 'CVSS-B',
        },
        {
            name: 'no-impact',
            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
            score: 0.0,
            nomenclature: 'CVSS-B',
        },
        {
            name: 'full-system-no-subsequent',
            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
            score: 9.3,
            nomenclature: 'CVSS-B',
        },
        {
            name: 'no-system-full-subsequent',
            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H',
            score: 7.9,
            nomenclature: 'CVSS-B',
        },
        {
            // This one verify the "full-impact" test case, with Threat intelligence
            // information, is effectively lowered.
            name: 'with-t',
            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U',
            score: 9.1,
            nomenclature: 'CVSS-BT',
        },
        {
            // This one verify the "full-impact" test case, with Threat intelligence
            // information and Environmental metrics set to higher constraints raise
            // the score.
            name: 'with-e',
            vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:L/MSA:S',
            score: 9.8,
            nomenclature: 'CVSS-BE',
        },
        {
            // This one only has a funny name :)
            name: 'smol',
            vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N',
            score: 1.0,
            nomenclature: 'CVSS-B',
        },
        // Those ones used Clement as a random source.
        // It enabled detecting multiple internal issues to the github.com/pandatix/go-cvss
        // Go module and a typo in the official calculator a week before publication.
        // Those have been adopted as part of the unit test corpus and should be kept for
        // regression testing.
        {
            name: 'clement-b',
            vector: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L',
            score: 5.2,
            nomenclature: 'CVSS-B',
        },
        {
            name: 'clement-bte',
            vector: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:A/MAT:P/MPR:N/MVI:H/MVA:N/MSI:H/MSA:N/S:N/V:C/U:Amber',
            score: 4.7,
            nomenclature: 'CVSS-BTE',
        },
        {
            name: 'reg-deptheq3eq6',
            vector: 'CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L',
            score: 5.8,
            nomenclature: 'CVSS-BE',
        },
        {
            name: 'RedHatProductSecurity/cvss-v4-calculator/#48',
            vector: 'CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U',
            score: 0.4,
            nomenclature: 'CVSS-BT'
        },
    ];

    testCases.forEach((testCase) => {
        test(testCase.name, () => {
            var vec = new CVSS40(testCase.vector);
            expect(vec.Score()).toBe(testCase.score);
            expect(vec.Nomenclature()).toBe(testCase.nomenclature);
        })
    });
});

import { CVSS31 } from '../src/cvss31';

describe('CVSS v3.1', () => {
    type TestCase = {
        name: string
        vector: string
    };
    describe('valid', () => {
        const testCases: TestCase[] = [
            {
                name: 'CVE-2021-28378',
                vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
            }, {
                name: 'CVE-2020-14144',
                vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
            }, {
                name: 'CVE-2021-44228',
                vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            }, {
                name: 'all-defined',
                vector: 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H',
            }, {
                name: 'whatever-order',
                vector: 'CVSS:3.1/I:L/MA:H/AR:H/UI:N/AC:H/C:H/AV:N/A:L/MUI:N/MI:H/RC:C/CR:H/IR:H/PR:L/MAV:N/MAC:L/MPR:N/E:H/MS:C/MC:H/RL:O/S:U',
            },
        ];

        testCases.forEach((testCase) => {
            test(testCase.name, () => {
                expect(new CVSS31(testCase.vector));
            });
        });
    });

    describe('invalid', () => {
        const testCases: TestCase[] = [
            {
                // This test case is inherited from the fuzz corpus of github.com/pandatix/go-cvss
                name: 'invalid-header',
                vector: '000003.1/AV:A/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
            },
        ];

        testCases.forEach((testCase) => {
            test(testCase.name, () => {
                expect(() => {
                    new CVSS31(testCase.vector)
                }).toThrow();
            });
        });
    })
});

test('Setter', () => {
    var vec = new CVSS31();
    expect(() => {
        vec.Set('C', 'L');
    });
    expect(() => {
        vec.Set('invalid', 'invalid');
    }).toThrow();
    expect(() => {
        vec.Set('C', 'invalid');
    }).toThrow();
});

describe('Score', () => {
    type TestCase = {
        name: string
        vector: string
        baseScore: number
        temporalScore: number
        environmentalScore: number
    };
    const testCases: TestCase[] = [
        {
            name: 'CVE-2021-28378',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',
            baseScore: 5.4,
            temporalScore: 5.4,
            environmentalScore: 5.4,
        }, {
            name: 'CVE-2020-14144',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 7.2,
            temporalScore: 7.2,
            environmentalScore: 7.2,
        }, {
            name: 'CVE-2021-44228',
            vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            baseScore: 10.0,
            temporalScore: 10.0,
            environmentalScore: 10.0,
        }, {
            name: 'all-defined',
            vector: 'CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/E:F/RL:U/RC:R/CR:H/IR:M/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H',
            baseScore: 7.1,
            temporalScore: 6.7,
            environmentalScore: 9.4,
        },
    ];

    testCases.forEach((testCase) => {
        test(testCase.name, () => {
            var vec = new CVSS31(testCase.vector);
            expect(vec.BaseScore()).toBe(testCase.baseScore);
            expect(vec.TemporalScore()).toBe(testCase.temporalScore);
            expect(vec.EnvironmentalScore()).toBe(testCase.environmentalScore);
        })
    });
});

import { CVSS30 } from '../src/cvss30';

describe('CVSS v3.0', () => {
    type TestCase = {
        name: string
        vector: string
    };
    describe('valid', () => {
        const testCases: TestCase[] = [
            {
                name: 'CVE-2021-4131',
                vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N'
            }, {
                name: 'CVE-2020-2931',
                vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            }, {
                name: 'all-defined',
                vector: 'CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:L/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H',
            }, {
                name: 'whatever-order',
                vector: 'CVSS:3.0/I:L/MA:H/AR:H/UI:N/AC:H/C:H/AV:A/A:L/MUI:N/MI:H/RC:C/CR:H/IR:H/PR:L/MAV:N/MAC:L/MPR:N/E:H/MS:C/MC:H/RL:O/S:U',
            },
        ];

        testCases.forEach((testCase) => {
            test(testCase.name, () => {
                expect(new CVSS30(testCase.vector));
            });
        });
    });

    describe('invalid', () => {
        const testCases: TestCase[] = [
            {
                name: 'invalid-header',
                vector: 'Something that does not start with CVSS:3.0'
            }, {
                name: 'invalid-metric-value',
                vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:InVaLiD/C:N/I:H/A:N'
            },
        ];

        testCases.forEach((testCase) => {
            test(testCase.name, () => {
                expect(() => {
                    new CVSS30(testCase.vector)
                }).toThrow();
            });
        });
    })
});

test('Setter', () => {
    var vec = new CVSS30();
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
            name: 'CVE-2021-4131',
            vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N',
            baseScore: 6.5,
            temporalScore: 6.5,
            environmentalScore: 6.5,
        }, {
            name: 'CVE-2020-2931',
            vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            baseScore: 9.8,
            temporalScore: 9.8,
            environmentalScore: 9.8,
        }, {
            name: 'all-defined',
            vector: 'CVSS:3.0/AV:A/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L/E:F/RL:U/RC:R/CR:H/IR:M/AR:L/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H',
            baseScore: 7.1,
            temporalScore: 6.7,
            environmentalScore: 9.4,
        },
    ];

    testCases.forEach((testCase) => {
        test(testCase.name, () => {
            var vec = new CVSS30(testCase.vector);
            expect(vec.BaseScore()).toBe(testCase.baseScore);
            expect(vec.TemporalScore()).toBe(testCase.temporalScore);
            expect(vec.EnvironmentalScore()).toBe(testCase.environmentalScore);
        })
    });
});

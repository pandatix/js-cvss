import { CVSS20 } from '../src/cvss20';

describe('CVSS v2.0', () => {
    type TestCase = {
        name: string
        vector: string
    };
    describe('valid', () => {
        const testCases: TestCase[] = [
            {
                name: 'CVSS v2.0 Guide Section 3.3.1 CVE-2002-0392',
                vector: 'AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C',
            }, {
                name: 'CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818',
                vector: 'AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C',
            }, {
                name: 'CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062',
                vector: 'AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C',
            }, {
                name: 'all-defined',
                vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M',
            }, {
                name: 'base-and-environmental',
                vector: 'AV:L/AC:M/Au:S/C:N/I:N/A:P/CDP:N/TD:ND/CR:M/IR:ND/AR:ND'
            }, {
                name: 'CVE-2022-39213',
                vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:C/E:U/RL:OF/RC:C/CDP:MH/TD:H/CR:M/IR:M/AR:M',
            }
        ];

        testCases.forEach((testCase) => {
            test(testCase.name, () => {
                expect(new CVSS20(testCase.vector));
            });
        });
    });
    describe('invalid', () => {
        const testCases: TestCase[] = [
            {
                name: 'invalid-last-metric',
                vector: 'AV:A/AC:L/Au:N/C:C/I:C/A:C/CDP:H/TD:H/CR:H/IR:ND/AR:H/',
            }, {
                name: 'invalid-metric-value',
                vector: 'AV:L/AC:L/Au:M/C:InVaLiD/I:P/A:N'
            }
        ];

        testCases.forEach((testCase) => {
            test(testCase.name, () => {
                expect(() => {
                    new CVSS20(testCase.vector)
                }).toThrow();
            });
        });
    });
});

test('Setter', () => {
    var vec = new CVSS20();
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
            name: 'CVSS v2.0 Guide Section 3.3.1 CVE-2002-0392',
            vector: 'AV:N/AC:L/Au:N/C:N/I:N/A:C/E:F/RL:OF/RC:C',
            baseScore: 7.8,
            temporalScore: 6.4,
            environmentalScore: 6.4,
        }, {
            name: 'CVSS v2.0 Guide Section 3.3.2 CVE-2003-0818',
            vector: 'AV:N/AC:L/Au:N/C:C/I:C/A:C/E:F/RL:OF/RC:C',
            baseScore: 10.0,
            temporalScore: 8.3,
            environmentalScore: 8.3,
        }, {
            name: 'CVSS v2.0 Guide Section 3.3.3 CVE-2003-0062',
            vector: 'AV:L/AC:H/Au:N/C:C/I:C/A:C/E:POC/RL:OF/RC:C',
            baseScore: 6.2,
            temporalScore: 4.9,
            environmentalScore: 4.9,
        },
    ];

    testCases.forEach((testCase) => {
        test(testCase.name, () => {
            var vec = new CVSS20(testCase.vector);
            expect(vec.BaseScore()).toBe(testCase.baseScore);
            expect(vec.TemporalScore()).toBe(testCase.temporalScore);
            expect(vec.EnvironmentalScore()).toBe(testCase.environmentalScore);
        })
    });
});

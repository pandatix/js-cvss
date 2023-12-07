import * as cvss40  from '../src/cvss40';

describe('CVSS v4.0 Section 7 test cases', () => {
    test('valid vectors', () => {
        expect(new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N'));
        expect(new cvss40.CVSS40('CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P'));
        expect(new cvss40.CVSS40('CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H'));
        expect(new cvss40.CVSS40('CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red'));
        expect(new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green'));
        // Specific one not from the specification, only here to have a rich API
        expect(new cvss40.CVSS40());
    });
    test('invalid vectors', () => {
        expect(() => {
            new cvss40.CVSS40('CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N');
        }).toThrow();
        expect(() => {
            new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/E:X');
        }).toThrow();
        expect(() => {
            new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/ui:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N');
        }).toThrow();
        expect(() => {
            new cvss40.CVSS40('AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N');
        }).toThrow();
        expect(() => {
            new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/SC:N/SI:N/SA:N');
        }).toThrow();
        expect(() => {
            new cvss40.CVSS40('CVSS:4.0/AC:L/AV:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/CR:L/IR:X/AR:L/RE:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/AT:N/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/E:U/S:N/AU:N/R:I/V:C/U:Green');
        }).toThrow();
        // Specific ones not from the specification, only to make sure of the full compliance
        expect(() => {
            new cvss40.CVSS40('');
        }).toThrow();
        expect(() => {
            new cvss40.CVSS40('toto CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N toto');
        }).toThrow();
    });
});

test('CVSS v4.0 vector', () => {
    // This test ensures it produces metrics in the proper order as defined in CVSS v4.0
    // specification Table 23, and it does not export undefined/X (Not Defined) metrics.
    const input = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green';
    var vec = new cvss40.CVSS40(input);
    expect(vec.Vector()).toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green');
});

test('Setter', () => {
    var vec = new cvss40.CVSS40();
    expect(() => {
        vec.Set('SA', 'H');
    });
    expect(() => {
        vec.Set('invalid', 'invalid');
    }).toThrow();
    expect(() => {
        vec.Set('SA', 'invalid');
    });
});

describe('Nomenclature', () => {
    test('CVSS-B', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N');
        expect(vec.Nomenclature()).toBe('CVSS-B');
    });
    test('CVSS-BT', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P');
        expect(vec.Nomenclature()).toBe('CVSS-BT');
    });
    test('CVSS-BE', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H');
        expect(vec.Nomenclature()).toBe('CVSS-BE');
    });
    test('CVSS-BTE', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green');
        expect(vec.Nomenclature()).toBe('CVSS-BTE');
    });
});

describe('Score', () => {
    test('full-impact', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')
        expect(vec.Score()).toBe(10.0);
        expect(vec.Nomenclature()).toBe('CVSS-B');
    });
    test('no-impact', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N')
        expect(vec.Score()).toBe(0.0);
        expect(vec.Nomenclature()).toBe('CVSS-B');
    });
    test('full-system-no-subsequent', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')
        expect(vec.Score()).toBe(9.3);
        expect(vec.Nomenclature()).toBe('CVSS-B');
    });
    test('no-system-full-subsequent', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H')
        expect(vec.Score()).toBe(7.9);
        expect(vec.Nomenclature()).toBe('CVSS-B');
    });
    test('with-t', () => {
        // This one verify the "full-impact" test case, with Threat intelligence
		// information, is effectively lowered.
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U')
        expect(vec.Score()).toBe(9.1);
        expect(vec.Nomenclature()).toBe('CVSS-BT');
    });
    test('with-e', () => {
        // This one verify the "full-impact" test case, with Threat intelligence
		// information, is effectively lowered.
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MVI:L/MSA:S')
        expect(vec.Score()).toBe(9.8);
        expect(vec.Nomenclature()).toBe('CVSS-BE');
    });
    test('smol', () => {
        // This one only has a funny name :)
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N')
        expect(vec.Score()).toBe(1.0);
        expect(vec.Nomenclature()).toBe('CVSS-B');
    });
    // Those ones used Clement as a random source.
    // It enabled detecting multiple internal issues to the github.com/pandatix/go-cvss
    // Go module and a typo in the official calculator a week before publication.
    // Those have been adopted as part of the unit test corpus and should be kept for
    // regression testing.
    test('clement-b', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L');
        expect(vec.Score()).toBe(5.2);
        expect(vec.Nomenclature()).toBe('CVSS-B');
    });
    test('clement-bte', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L/E:P/CR:H/IR:M/AR:H/MAV:A/MAT:P/MPR:N/MVI:H/MVA:N/MSI:H/MSA:N/S:N/V:C/U:Amber')
        expect(vec.Score()).toBe(4.7);
        expect(vec.Nomenclature()).toBe('CVSS-BTE');
    });
    test('reg-deptheq3eq6', () => {
        var vec = new cvss40.CVSS40('CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:H/SC:H/SI:H/SA:H/CR:L/IR:L/AR:L')
        expect(vec.Score()).toBe(5.8);
        expect(vec.Nomenclature()).toBe('CVSS-BE');
    });
});

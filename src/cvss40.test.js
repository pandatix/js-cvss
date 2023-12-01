const cvss40 = require('./cvss40');
const errors = require('./errors')

describe('CVSS v4.0 Section 7 test cases', () => {
    test('valid vectors', () => {
        expect(new cvss40.CVSS40("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"));
        expect(new cvss40.CVSS40("CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:P"));
        expect(new cvss40.CVSS40("CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H/CR:H/IR:H/AR:M/MAV:N/MAC:L/MAT:P/MPR:L/MUI:A/MVC:N/MVI:H/MVA:L/MSC:L/MSI:S/MSA:H"));
        expect(new cvss40.CVSS40("CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L/E:A/S:P/AU:Y/R:A/V:D/RE:L/U:Red"));
        expect(new cvss40.CVSS40("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green"));
        // Specific one not from the specification, only here to have a rich API
        expect(new cvss40.CVSS40());
    });
    test('invalid vectors', () => {
        expect(() => {
            new cvss40.CVSS40("CVSS:4.0/AV:F/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N");
        }).toThrow(errors.InvalidVector);
        expect(() => {
            new cvss40.CVSS40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:A/E:X");
        }).toThrow(errors.InvalidVector);
        expect(() => {
            new cvss40.CVSS40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/ui:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N");
        }).toThrow(errors.InvalidVector);
        expect(() => {
            new cvss40.CVSS40("AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N");
        }).toThrow(errors.InvalidVector);
        expect(() => {
            new cvss40.CVSS40("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/SC:N/SI:N/SA:N");
        }).toThrow(errors.InvalidVector);
        expect(() => {
            new cvss40.CVSS40("CVSS:4.0/AC:L/AV:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/CR:L/IR:X/AR:L/RE:H/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/AT:N/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/E:U/S:N/AU:N/R:I/V:C/U:Green");
        }).toThrow(errors.InvalidVector);
        // Specific ones not from the specification, only to make sure of the full compliance
        expect(() => {
            new cvss40.CVSS40("");
        }).toThrow(errors.InvalidVector);
        expect(() => {
            new cvss40.CVSS40("toto CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N toto");
        }).toThrow(errors.InvalidVector);
    });
});

test('CVSS v4.0 vector', () => {
    // This test ensures it produces metrics in the proper order as defined in CVSS v4.0
    // specification Table 23, and it does not export undefined/X (Not Defined) metrics.
    const input = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/IR:X/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVC:X/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green";
    var vec = new cvss40.CVSS40(input);
    expect(vec.Vector()).toBe("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/CR:L/AR:L/MAV:A/MAC:H/MAT:N/MPR:N/MUI:P/MVI:N/MVA:H/MSC:N/MSI:L/MSA:S/S:N/AU:N/R:I/V:C/RE:H/U:Green");
});

test('Setter', () => {
    var vec = new cvss40.CVSS40();
    expect(() => {
        vec.Set("SA", "H");
    });
    expect(() => {
        vec.Set("invalid", "invalid")
    }).toThrow();
    expect(() => {
        vec.Set("SA", "invalid")
    });
});

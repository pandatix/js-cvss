const errors = require('./errors')

// Comes from https://www.first.org/cvss/cvss-v4.0.json, slightly modified
// to match the metric groups without false-positives and to avoid double-capture
// of Provider Urgency (U) due to multi-char values.
const re = /^CVSS:4[.]0(\/AV:[NALP])(\/AC:[LH])(\/AT:[NP])(\/PR:[NLH])(\/UI:[NPA])(\/VC:[HLN])(\/VI:[HLN])(\/VA:[HLN])(\/SC:[HLN])(\/SI:[HLN])(\/SA:[HLN])(\/E:[XAPU])?(\/CR:[XHML])?(\/IR:[XHML])?(\/AR:[XHML])?(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MAT:[XNP])?(\/MPR:[XNLH])?(\/MUI:[XNPA])?(\/MVC:[XNLH])?(\/MVI:[XNLH])?(\/MVA:[XNLH])?(\/MSC:[XNLH])?(\/MSI:[XNLHS])?(\/MSA:[XNLHS])?(\/S:[XNP])?(\/AU:[XNY])?(\/R:[XAUI])?(\/V:[XDC])?(\/RE:[XLMH])?(\/U:(?:X|Clear|Green|Amber|Red))?$/g;

const isDefined = ((metric) => this.Get(metric) != undefined && this.Get("E") != "X");

// Metrics defined in Table 23
const metrics = {
    // Base (11 metrics)
    "AV": ["N", "A", "L", "P"],
    "AC": ["L", "H"],
    "AT": ["N", "P"],
    "PR": ["N", "L", "H"],
    "UI": ["N", "P", "A"],
    "VC": ["H", "L", "N"],
    "VI": ["H", "L", "N"],
    "VA": ["H", "L", "N"],
    "SC": ["H", "L", "N"],
    "SI": ["H", "L", "N"],
    "SA": ["H", "L", "N"],
    // Threat (1 metric)
    "E": ["X", "A", "P", "U"],
    // Environmental (14 metrics)
    "CR":  ["X", "H", "M", "L"],
    "IR":  ["X", "H", "M", "L"],
    "AR":  ["X", "H", "M", "L"],
    "MAV": ["X", "N", "A", "L", "P"],
    "MAC": ["X", "L", "H"],
    "MAT": ["X", "N", "P"],
    "MPR": ["X", "N", "L", "H"],
    "MUI": ["X", "N", "P", "A"],
    "MVC": ["X", "H", "L", "N"],
    "MVI": ["X", "H", "L", "N"],
    "MVA": ["X", "H", "L", "N"],
    "MSC": ["X", "H", "L", "N"],
    "MSI": ["X", "S", "H", "L", "N"],
    "MSA": ["X", "S", "H", "L", "N"],
    // Supplemental (6 metrics)
    "S":  ["X", "N", "P"],
    "AU": ["X", "N", "Y"],
    "R":  ["X", "A", "U", "I"],
    "V":  ["X", "D", "C"],
    "RE": ["X", "L", "M", "H"],
    "U":  ["X", "Clear", "Green", "Amber", "Red"],
}

class CVSS40 {
    constructor(vector='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N') {
        this.metrics = {};

        this.parse(vector);
    }

    // parse makes use of the regex for code simplicity, but we could
    // use the `metrics` constant to provide better accurate error messages.
    parse(vector) {
        // Ensure input is valid according to the regular expression
        var matches = [...vector.matchAll(re)][0];
        if (matches == undefined) {
            throw errors.InvalidVector;
        }
        // Skip prefix
        matches.shift();
        // Parse each metric group
        for (var match of matches) {
            if (match == undefined) {
                continue;
            }
            match = match.slice(1);
            var [key, value] = match.split(":");
            this.metrics[key] = value;
        }
    }

    Vector() {
        var vector = "CVSS:4.0";
        for (const [om] of Object.entries(metrics)) {
            var metric = this.Get(om);
            // Add the value iif was set and is not "X" (Not Defined)
            if (metric == undefined || metric == "X") {
               continue;
           }
           vector = vector.concat("/", om, ":", metric);
        }
        return vector;
    }
    Get(metric) {
        return this.metrics[metric];
    }
    Set(metric, value) {
        for (const [om, values] of Object.entries(metrics)) {
            if (om == metric) {
                if (values.any(value)) {
                    this.metrics[metric] = value;
                    return;
                }
                throw new errors.InvalidMetricValue(metric, value);
            }
        }
        throw new errors.InvalidMetric(metric);
    }
    Score() { }
    Nomenclature() {
        var t = (["E"]).every(isDefined);
        var e = (["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]).every(isDefined);

        if (t) {
            if (e) {
                return "CVSS-BTE";
            }
            return "CVSS-BT";
        }
        if (e) {
            return "CVSS-BE";
        }
        return "CVSS-B";
    }
};

const Rating = function (score) {
    if (score < 0 || score > 10) {
        throw new ErrOutOfBoundsScore();
    }
    if (score >= 9.0) {
        return "CRITICAL"
    }
    if (score >= 7.0) {
        return "HIGH"
    }
    if (score >= 4.0) {
        return "MEDIUM"
    }
    if (score >= 0.1) {
        return "LOW"
    }
    return "NONE"
}

module.exports = { CVSS40, Rating };

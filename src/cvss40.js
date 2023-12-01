const errors = require('./errors')

// Comes from https://www.first.org/cvss/cvss-v4.0.json, slightly modified
// to match the metric groups without false-positives and to avoid double-capture
// of Provider Urgency (U) due to multi-char values.
const re = /^CVSS:4[.]0(\/AV:[NALP])(\/AC:[LH])(\/AT:[NP])(\/PR:[NLH])(\/UI:[NPA])(\/VC:[HLN])(\/VI:[HLN])(\/VA:[HLN])(\/SC:[HLN])(\/SI:[HLN])(\/SA:[HLN])(\/E:[XAPU])?(\/CR:[XHML])?(\/IR:[XHML])?(\/AR:[XHML])?(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MAT:[XNP])?(\/MPR:[XNLH])?(\/MUI:[XNPA])?(\/MVC:[XNLH])?(\/MVI:[XNLH])?(\/MVA:[XNLH])?(\/MSC:[XNLH])?(\/MSI:[XNLHS])?(\/MSA:[XNLHS])?(\/S:[XNP])?(\/AU:[XNY])?(\/R:[XAUI])?(\/V:[XDC])?(\/RE:[XLMH])?(\/U:(?:X|Clear|Green|Amber|Red))?$/g;

const ordering = [
    // Base (11 metrics)
    "AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA",
    // Threat (1 metric)
    "E",
    // Environmental (14 metrics)
    "CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA",
    // Supplemental (6 metrics)
    "S", "AU", "R", "V", "RE", "U",
]

class CVSS40 {
    constructor(vector) {
        this.metrics = {};

        this.parse(vector);
    }

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
        for (const om of ordering) {
            var metric = this.Get(om)
            if (metric == undefined) {
                continue
            }
            vector = vector.concat("/", om, ":", metric)
        }
        return vector
    }
    Get(metric) {
        return this.metrics[metric]
    }
    Set(metric, value) { }
    Score() { }
    Nomenclature() { }
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

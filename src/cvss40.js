const errors = require('./errors')

// Comes from https://www.first.org/cvss/cvss-v4.0.json, slightly modified
// to match the metric groups without false-positives and to avoid double-capture
// of Provider Urgency (U) due to multi-char values.
const re = /^CVSS:4[.]0(\/AV:[NALP])(\/AC:[LH])(\/AT:[NP])(\/PR:[NLH])(\/UI:[NPA])(\/VC:[HLN])(\/VI:[HLN])(\/VA:[HLN])(\/SC:[HLN])(\/SI:[HLN])(\/SA:[HLN])(\/E:[XAPU])?(\/CR:[XHML])?(\/IR:[XHML])?(\/AR:[XHML])?(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MAT:[XNP])?(\/MPR:[XNLH])?(\/MUI:[XNPA])?(\/MVC:[XNLH])?(\/MVI:[XNLH])?(\/MVA:[XNLH])?(\/MSC:[XNLH])?(\/MSI:[XNLHS])?(\/MSA:[XNLHS])?(\/S:[XNP])?(\/AU:[XNY])?(\/R:[XAUI])?(\/V:[XDC])?(\/RE:[XLMH])?(\/U:(?:X|Clear|Green|Amber|Red))?$/g;

class CVSS40 {
    constructor(vector) {
        this.metrics = {};

        this.parse(vector);
    }

    parse(vector) {
        var matches = [...vector.matchAll(re)][0];
        if (matches == undefined) {
            throw errors.InvalidVector;
        }
        matches.shift();
        for (var match of matches) {
            if (match == undefined) {
                continue;
            }
            match = match.slice(1);
            var [key, value] = match.split(":");
            this.metrics[key] = value;
        }
    }

    Vector() { }
    Get(metric) { }
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

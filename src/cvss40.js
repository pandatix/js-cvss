const errors = require('./errors');
const lookup = require('./lookup');

// Comes from https://www.first.org/cvss/cvss-v4.0.json, slightly modified
// to match the metric groups without false-positives and to avoid double-capture
// of Provider Urgency (U) due to multi-char values.
const re = /^CVSS:4[.]0(\/AV:[NALP])(\/AC:[LH])(\/AT:[NP])(\/PR:[NLH])(\/UI:[NPA])(\/VC:[HLN])(\/VI:[HLN])(\/VA:[HLN])(\/SC:[HLN])(\/SI:[HLN])(\/SA:[HLN])(\/E:[XAPU])?(\/CR:[XHML])?(\/IR:[XHML])?(\/AR:[XHML])?(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MAT:[XNP])?(\/MPR:[XNLH])?(\/MUI:[XNPA])?(\/MVC:[XNLH])?(\/MVI:[XNLH])?(\/MVA:[XNLH])?(\/MSC:[XNLH])?(\/MSI:[XNLHS])?(\/MSA:[XNLHS])?(\/S:[XNP])?(\/AU:[XNY])?(\/R:[XAUI])?(\/V:[XDC])?(\/RE:[XLMH])?(\/U:(?:X|Clear|Green|Amber|Red))?$/g;

class CVSS40 {
    #metrics = {};

    constructor(vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N') {
        this.#parse(vector);
    }

    // parse makes use of the regex for code simplicity, but we could
    // use the `metrics` constant to provide better accurate error messages.
    #parse(vector) {
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
            var [key, value] = match.split(':');
            this.#metrics[key] = value;
        }
    }

    Vector() {
        var vector = 'CVSS:4.0';
        for (const [om] of Object.entries(lookup.table23)) {
            var metric = this.Get(om);
            // Add the value iif was set and is not 'X' (Not Defined)
            if (metric == undefined || metric == 'X') {
                continue;
            }
            vector = vector.concat('/', om, ':', metric);
        }
        return vector;
    }
    Get(metric) {
        return this.#metrics[metric];
    }
    Set(metric, value) {
        for (const [om, values] of Object.entries(looku.table23)) {
            if (om == metric) {
                if (values.any(value)) {
                    this.#metrics[metric] = value;
                    return;
                }
                throw new errors.InvalidMetricValue(metric, value);
            }
        }
        throw new errors.InvalidMetric(metric);
    }
    // Implementation internals are largely based upon https://github.com/pandatix/go-cvss
    // submodule 40.
    Score() {
        // If the vulnerability does not affect the system AND the subsequent
        // system, there is no reason to try scoring what has no risk and impact.
        if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((met) => this.#getReal(met) == "N")) {
            return 0.0
        }

        var mv = this.#macrovector();
        var eq1 = Number(mv[0]);
        var eq2 = Number(mv[1]);
        var eq3 = Number(mv[2]);
        var eq4 = Number(mv[3]);
        var eq5 = Number(mv[4]);
        var eq6 = Number(mv[5]);
        var eqsv = lookup.mv[mv];

        // Compute EQs next lower MacroVector
        // -> As the lower the EQ value is the bigger, the next lower MacroVector
        //    would be +1 to this one
        // -> If not possible (level+1 > #level), it is set to NaN
        var lower = 0;
        var eq1nlm = NaN;
        if (eq1 < 2) { // 2 = maximum level for EQ1
            eq1nlm = lookup.mv[String(eq1 + 1) + String(eq2) + String(eq3) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        }
        var eq2nlm = NaN;
        if (eq2 < 1) { // 1 = maximum level for EQ2
            eq2nlm = lookup.mv[String(eq1) + String(eq2 + 1) + String(eq3) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        }
        var eq4nlm = NaN;
        if (eq4 < 2) { // 2 = maximum level for EQ4
            eq4nlm = lookup.mv[String(eq1) + String(eq2) + String(eq3) + String(eq4 + 1) + String(eq5) + String(eq6)];
            lower++;
        }
        var eq5nlm = NaN;
        if (eq5 < 2) { // 2 = maximum level for EQ5
            eq5nlm = lookup.mv[String(eq1) + String(eq2) + String(eq3) + String(eq4) + String(eq5 + 1) + String(eq6)];
            lower++;
        }
        // /!\ As EQ3 and EQ6 are related, we can't do the same as it could produce
        // eq3=2 and eq6=0 which is impossible thus will have a lookup (for EQ3) of 0.
        // This would fail the further computations.
        var eq3eq6nlm = NaN;
        if (eq3 == 1 && eq6 == 1) {
            // 11 -> 21
            eq3eq6nlm = lookup.mv[String(eq1) + String(eq2) + String(eq3 + 1) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        } else if (eq3 == 0 && eq6 == 1) {
            // 01 -> 11
            eq3eq6nlm = lookup.mv[String(eq1) + String(eq2) + String(eq3 + 1) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        } else if (eq3 == 1 && eq6 == 0) {
            // 10 -> 11
            eq3eq6nlm = lookup.mv[String(eq1) + String(eq2) + String(eq3) + String(eq4) + String(eq5) + String(eq6 + 1)];
            lower++;
        } else if (eq3 == 0 && eq6 == 0) {
            // 00 -> 01 OR 00 -> 10, takes the bigger
            eq3eq6nlm = Math.max(lookup.mv[String(eq1) + String(eq2) + String(eq3 + 1) + String(eq4) + String(eq5) + String(eq6)], lookup.mv[String(eq1) + String(eq2) + String(eq3) + String(eq4) + String(eq5) + String(eq6 + 1)]);
            lower++;
        }

        // 1.a - Compute maximal scoring (absolute) differences
        const msd = ((nlm) => {
            var msd = Math.abs(nlm - eqsv);
            if (isNaN(msd)) {
                return 0;
            }
            return msd;
        })
        var eq1msd = msd(eq1nlm);
        var eq2msd = msd(eq2nlm);
        var eq3eq6msd = msd(eq3eq6nlm);
        var eq4msd = msd(eq4nlm);
        var eq5msd = msd(eq5nlm);

        // 1.b - Compute the severity distances of the to-be scored vectors
        //       to a highest AND higher severity vector in the MacroVector
        var eq1svdst = 0, eq2svdst = 0, eq3eq6svdst = 0, eq4svdst = 0, eq5svdst = 0;
        for (const eq1mx of lookup.highestSeverityVectors[1][eq1]) {
            for (const eq2mx of lookup.highestSeverityVectors[2][eq2]) {
                for (const eq3eq6mx of lookup.highestSeverityVectors[3][eq3][eq6]) {
                    for (const eq4mx of lookup.highestSeverityVectors[4][eq4]) {
                        // Don't need to iterate over eq5, only one dimension is involved
                        // so the highest of a MV's EQ is always unique, such that iterating
                        // over it would lead to nothing but cognitive complexity.

                        var partial = [eq1mx, eq2mx, eq3eq6mx, eq4mx].join('/');

                        // Compute severity distances
                        var avsvdst = this.#severityDistance('AV', this.#getReal('AV'), getValue(partial, 'AV'));
                        var prsvdst = this.#severityDistance('PR', this.#getReal('PR'), getValue(partial, 'PR'));
                        var uisvdst = this.#severityDistance('UI', this.#getReal('UI'), getValue(partial, 'UI'));

                        var acsvdst = this.#severityDistance('AC', this.#getReal('AC'), getValue(partial, 'AC'));
                        var atsvdst = this.#severityDistance('AT', this.#getReal('AT'), getValue(partial, 'AT'));

                        var vcsvdst = this.#severityDistance('VC', this.#getReal('VC'), getValue(partial, 'VC'));
                        var visvdst = this.#severityDistance('VI', this.#getReal('VI'), getValue(partial, 'VI'));
                        var vasvdst = this.#severityDistance('VA', this.#getReal('VA'), getValue(partial, 'VA'));

                        var scsvdst = this.#severityDistance('SC', this.#getReal('SC'), getValue(partial, 'SC'));
                        var sisvdst = this.#severityDistance('SI', this.#getReal('SI'), getValue(partial, 'SI'));
                        var sasvdst = this.#severityDistance('SA', this.#getReal('SA'), getValue(partial, 'SA'));

                        var crsvdst = this.#severityDistance('CR', this.#getReal('CR'), getValue(partial, 'CR'));
                        var irsvdst = this.#severityDistance('IR', this.#getReal('IR'), getValue(partial, 'IR'));
                        var arsvdst = this.#severityDistance('AR', this.#getReal('AR'), getValue(partial, 'AR'));

                        if ([avsvdst, prsvdst, uisvdst, acsvdst, atsvdst, vcsvdst, visvdst, vasvdst, scsvdst, sisvdst, sasvdst, crsvdst, irsvdst, arsvdst].some((met) => met < 0)) {
                            continue;
                        }

                        eq1svdst = avsvdst + prsvdst + uisvdst;
                        eq2svdst = acsvdst + atsvdst;
                        eq3eq6svdst = vcsvdst + visvdst + vasvdst + crsvdst + irsvdst + arsvdst;
                        eq4svdst = scsvdst + sisvdst + sasvdst;
                        // Don't need to compute E severity distance as the maximum will
					    // always remain the same due to only 1 dimension involved in EQ5.
                        eq5svdst = 0;
                        break;
                    }
                }
            }
        }

        // 1.c - Compute proportion of the distance
        var eq1prop = eq1svdst / (lookup.depth[1][eq1] + 1);
        var eq2prop = eq2svdst / (lookup.depth[2][eq2] + 1);
        var eq3eq6prop = eq3eq6svdst / (lookup.depth[3][eq3][eq6] + 1);
        var eq4prop = eq4svdst / (lookup.depth[4][eq4] + 1);
        var eq5prop = eq5svdst / (lookup.depth[5][eq5] + 1);

        // 1.d - Multiply maximal scoring diff. by prop. of distance
        eq1msd *= eq1prop;
        eq2msd *= eq2prop;
        eq3eq6msd *= eq3eq6prop;
        eq4msd *= eq4prop;
        eq5msd *= eq5prop;
        
        // 2 - Compute mean
        var mean = 0;
        if (lower != 0) {
            mean = (eq1msd + eq2msd + eq3eq6msd + eq4msd + eq5msd) / lower;
        }

        // 3 - Compute score
        return Number(roundup(eqsv - mean));
    }
    Nomenclature() {
        const isDefined = ((metric) => this.Get(metric) != undefined && this.Get('E') != 'X');
        var t = (['E']).some(isDefined);
        var e = (['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA']).some(isDefined);

        if (t) {
            if (e) {
                return 'CVSS-BTE';
            }
            return 'CVSS-BT';
        }
        if (e) {
            return 'CVSS-BE';
        }
        return 'CVSS-B';
    }

    #getReal(metric) {
        var v = this.Get('M' + metric)
        if (v != undefined && v != 'X') {
            return v
        }
        v = this.Get(metric)
        if (v == undefined) {
            switch (metric) {
                case 'CR':
                case 'IR':
                case 'AR':
                    return 'H';
                case 'E':
                    return 'A';
            }
        }
        return v
    }
    #macrovector() {
        var av = this.#getReal('AV');
        var ac = this.#getReal('AC');
        var at = this.#getReal('AT');
        var pr = this.#getReal('PR');
        var ui = this.#getReal('UI');
        var vc = this.#getReal('VC');
        var vi = this.#getReal('VI');
        var va = this.#getReal('VA');
        var sc = this.#getReal('SC');
        var msi = this.Get('MSI');
        var si = this.#getReal('SI');
        var msa = this.Get('MSA');
        var sa = this.#getReal('SA');
        var e = this.Get('E');
        var cr = this.Get('CR');
        var ir = this.Get('IR');
        var ar = this.Get('AR');

        // Compte MacroVectors
        // => EQ1
        var eq1 = '0';
        if (av == 'N' && pr == 'N' && ui == 'N') {
            eq1 = '0';
        } else if ((av == 'N' || pr == 'N' || ui == 'N') && !(av == 'N' && pr == 'N' && ui == 'N') && !(av == 'P')) {
            eq1 = '1';
        } else if (av == 'P' || !(av == 'N' || pr == 'N' || ui == 'N')) {
            eq1 = '2';
        }

        // EQ2
        var eq2 = '0';
        if (!(ac == 'L' && at == 'N')) {
            eq2 = '1';
        }

        // EQ3
        var eq3 = '0';
        if (vc == 'H' && vi == 'H') {
            eq3 = '0';
        } else if (!(vc == 'H' && vi == 'H') && (vc == 'H' || vi == 'H' || va == 'H')) {
            eq3 = '1';
        } else if (!(vc == 'H' || vi == 'H' || va == 'H')) {
            eq3 = '2';
        }

        // EQ4
        var eq4 = '0';
        if (msi == 'S' || msa == 'S') {
            eq4 = '0';
        } else if (!(msi == 'S' || msa == 'S') && (sc == 'H' || si == 'H' || sa == 'H')) {
            eq4 = '1';
        } else if (!(msi == 'S' || msa == 'S') && !(sc == 'H' || si == 'H' || sa == 'H')) {
            eq4 = '2';
        }

        // EQ5
        var eq5 = '0';
        if (e == 'A' || e == 'X' || e == undefined) {
            eq5 = '0';
        } else if (e == 'P') {
            eq5 = '1';
        } else if (e == 'U') {
            eq5 = '2';
        }

        // EQ6
        var eq6 = '0';
        var crh = (cr == 'H' || cr == 'X' || cr == undefined);
        var irh = (ir == 'H' || ir == 'X' || ir == undefined);
        var arh = (ar == 'H' || ar == 'X' || ar == undefined);
        if ((crh && vc == 'H') || (irh && vi == 'H') || (arh && va == 'H')) {
            eq6 = '0';
        } else if (!(crh && vc == 'H') && !(irh && vi == 'H') && !(arh && va == 'H')) {
            eq6 = '1';
        }

        return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
    }
    #severityDistance(metric, vecVal, mxVal) {
        var values = lookup.sevIdx[metric];
        return values.indexOf(vecVal) - values.indexOf(mxVal);
    }
};

const getValue = function (partial, metric) {
    var pts = partial.split('/');
    for (const pt of pts) {
        [key, value] = pt.split(':');
        if (key == metric) {
            return value;
        }
    }
}

const roundup = function(score) {
    return score.toFixed(1);
}

const Rating = function (score) {
    if (score < 0 || score > 10) {
        throw new ErrOutOfBoundsScore();
    }
    if (score >= 9.0) {
        return 'CRITICAL';
    }
    if (score >= 7.0) {
        return 'HIGH';
    }
    if (score >= 4.0) {
        return 'MEDIUM';
    }
    if (score >= 0.1) {
        return 'LOW';
    }
    return 'NONE';
}

module.exports = { CVSS40, Rating };

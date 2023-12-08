import * as errors from './errors';
import * as lookup from './lookup';

// Comes from https://www.first.org/cvss/cvss-v4.0.json, slightly modified
// to match the metric groups without false-positives and to avoid double-capture
// of Provider Urgency (U) due to multi-char values.
const re = /^CVSS:4[.]0(\/AV:[NALP])(\/AC:[LH])(\/AT:[NP])(\/PR:[NLH])(\/UI:[NPA])(\/VC:[HLN])(\/VI:[HLN])(\/VA:[HLN])(\/SC:[HLN])(\/SI:[HLN])(\/SA:[HLN])(\/E:[XAPU])?(\/CR:[XHML])?(\/IR:[XHML])?(\/AR:[XHML])?(\/MAV:[XNALP])?(\/MAC:[XLH])?(\/MAT:[XNP])?(\/MPR:[XNLH])?(\/MUI:[XNPA])?(\/MVC:[XNLH])?(\/MVI:[XNLH])?(\/MVA:[XNLH])?(\/MSC:[XNLH])?(\/MSI:[XNLHS])?(\/MSA:[XNLHS])?(\/S:[XNP])?(\/AU:[XNY])?(\/R:[XAUI])?(\/V:[XDC])?(\/RE:[XLMH])?(\/U:(?:X|Clear|Green|Amber|Red))?$/g;

/**
 * Implementation of the CVSS v4.0 specification (https://www.first.org/cvss/v4.0/specification-document).
 */
export class CVSS40 {
    private _metrics = {
        // Set default values of non-mandatory metrics : Not Defined (X)
        // => Threat
        'E': 'X',
        // => Environmental
        'CR': 'X', 'IR': 'X', 'AR': 'X', 'MAV': 'X', 'MAC': 'X', 'MAT': 'X', 'MPR': 'X', 'MUI': 'X', 'MVC': 'X', 'MVI': 'X', 'MVA': 'X', 'MSC': 'X', 'MSI': 'X', 'MSA': 'X',
        // => Supplemental
        'S': 'X', 'AU': 'X', 'R': 'X', 'V': 'X', 'RE': 'X', 'U': 'X',
    };

    /**
     * Construct a CVSS v4.0 object, and parse the vector if provided.
     * If not, the Base metrics is set to the default values (score = 0).
     * 
     * @param vector The vector to parse.
     * @throws When the vector is invalid.
     */
    constructor(vector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N') {
        this.parse(vector);
    }

    /**
     * Parse the provided vector.
     * Makes use of the regex for code simplicity, but we could use the
     * `metrics` constant to provide better accurate error messages.
     * 
     * @param vector The vector to parse.
     * @throws When the vector is invalid.
     */
    private parse(vector: string) {
        // Ensure input is valid according to the regular expression
        let matches = [...vector.matchAll(re)][0];
        if (matches == null) {
            throw new Error('invalid CVSS v4.0 vector');
        }
        // Skip prefix
        matches.shift();
        // Parse each metric group
        for (let match of matches) {
            if (match == undefined) {
                continue;
            }
            match = match.slice(1);
            const pts = match.split(':');
            this._metrics[pts[0]] = pts[1];
        }
    }

    /**
     * Return the vector string representation of the CVSS v4.0 object.
     * 
     * @return The vector string representation.
     */
    Vector() {
        let vector = 'CVSS:4.0';
        for (const [om] of Object.entries(lookup.table23)) {
            const metric = this.Get(om);
            // Add the value iif was set and is not 'X' (Not Defined)
            if (metric == undefined || metric == 'X') {
                continue;
            }
            vector = vector.concat('/', om, ':', metric);
        }
        return vector;
    }
    /**
     * Get the metric value given its value (e.g. 'AV').
     * 
     * @param metric The metric to get the value of.
     * @return The corresponding metric value.
     * @throws Metric does not exist.
     */
    Get(metric: string): string {
        const v = this._metrics[metric];
        if (v == undefined) {
            throw new errors.InvalidMetric(metric);
        }
        return v;
    }
    /**
     * Set the metric value given its key and value (e.g. 'AV' and 'L').
     * 
     * @param metric The metric to set the value of.
     * @param value The corresponding metric value.
     * @throws Metric does not exist or has an invalid value.
     */
    Set(metric: string, value: string) {
        for (const [om, values] of Object.entries(lookup.table23)) {
            if (om == metric) {
                if (values.indexOf(value) != -1) {
                    this._metrics[metric] = value;
                    return;
                }
                throw new errors.InvalidMetricValue(metric, value);
            }
        }
        throw new errors.InvalidMetric(metric);
    }
    /**
     * Compute the CVSS v4.0 Score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 40.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    Score(): number {
        // If the vulnerability does not affect the system AND the subsequent
        // system, there is no reason to try scoring what has no risk and impact.
        if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((met) => this.getReal(met) == "N")) {
            return 0.0
        }

        const mv = this.macrovector();
        const eq1 = Number(mv[0]);
        const eq2 = Number(mv[1]);
        const eq3 = Number(mv[2]);
        const eq4 = Number(mv[3]);
        const eq5 = Number(mv[4]);
        const eq6 = Number(mv[5]);
        const eqsv: number = lookup.mv[mv];

        // Compute EQs next lower MacroVector
        // -> As the lower the EQ value is the bigger, the next lower MacroVector
        //    would be +1 to this one
        // -> If not possible (level+1 > level), it is set to NaN
        let lower = 0;
        let eq1nlm = NaN;
        if (eq1 < 2) { // 2 = maximum level for EQ1
            eq1nlm = lookup.mv[String(eq1 + 1) + String(eq2) + String(eq3) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        }
        let eq2nlm = NaN;
        if (eq2 < 1) { // 1 = maximum level for EQ2
            eq2nlm = lookup.mv[String(eq1) + String(eq2 + 1) + String(eq3) + String(eq4) + String(eq5) + String(eq6)];
            lower++;
        }
        let eq4nlm = NaN;
        if (eq4 < 2) { // 2 = maximum level for EQ4
            eq4nlm = lookup.mv[String(eq1) + String(eq2) + String(eq3) + String(eq4 + 1) + String(eq5) + String(eq6)];
            lower++;
        }
        let eq5nlm = NaN;
        if (eq5 < 2) { // 2 = maximum level for EQ5
            eq5nlm = lookup.mv[String(eq1) + String(eq2) + String(eq3) + String(eq4) + String(eq5 + 1) + String(eq6)];
            lower++;
        }
        // /!\ As EQ3 and EQ6 are related, we can't do the same as it could produce
        // eq3=2 and eq6=0 which is impossible thus will have a lookup (for EQ3) of 0.
        // This would fail the further computations.
        let eq3eq6nlm = NaN;
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
        const msd = ((nlm: number): number => {
            let msd = Math.abs(nlm - eqsv);
            if (isNaN(msd)) {
                return 0;
            }
            return msd;
        })
        let eq1msd = msd(eq1nlm);
        let eq2msd = msd(eq2nlm);
        let eq3eq6msd = msd(eq3eq6nlm);
        let eq4msd = msd(eq4nlm);
        let eq5msd = msd(eq5nlm);

        // 1.b - Compute the severity distances of the to-be scored vectors
        //       to a highest AND higher severity vector in the MacroVector
        let eq1svdst = 0, eq2svdst = 0, eq3eq6svdst = 0, eq4svdst = 0, eq5svdst = 0;
        for (const eq1mx of lookup.highestSeverityVectors[1][eq1]) {
            for (const eq2mx of lookup.highestSeverityVectors[2][eq2]) {
                for (const eq3eq6mx of lookup.highestSeverityVectors[3][eq3][eq6]) {
                    for (const eq4mx of lookup.highestSeverityVectors[4][eq4]) {
                        // Don't need to iterate over eq5, only one dimension is involved
                        // so the highest of a MV's EQ is always unique, such that iterating
                        // over it would lead to nothing but cognitive complexity.

                        const partial = [eq1mx, eq2mx, eq3eq6mx, eq4mx].join('/');

                        // Compute severity distances
                        const avsvdst = this.severityDistance('AV', this.getReal('AV'), getValue(partial, 'AV'));
                        const prsvdst = this.severityDistance('PR', this.getReal('PR'), getValue(partial, 'PR'));
                        const uisvdst = this.severityDistance('UI', this.getReal('UI'), getValue(partial, 'UI'));

                        const acsvdst = this.severityDistance('AC', this.getReal('AC'), getValue(partial, 'AC'));
                        const atsvdst = this.severityDistance('AT', this.getReal('AT'), getValue(partial, 'AT'));

                        const vcsvdst = this.severityDistance('VC', this.getReal('VC'), getValue(partial, 'VC'));
                        const visvdst = this.severityDistance('VI', this.getReal('VI'), getValue(partial, 'VI'));
                        const vasvdst = this.severityDistance('VA', this.getReal('VA'), getValue(partial, 'VA'));

                        const scsvdst = this.severityDistance('SC', this.getReal('SC'), getValue(partial, 'SC'));
                        const sisvdst = this.severityDistance('SI', this.getReal('SI'), getValue(partial, 'SI'));
                        const sasvdst = this.severityDistance('SA', this.getReal('SA'), getValue(partial, 'SA'));

                        const crsvdst = this.severityDistance('CR', this.getReal('CR'), getValue(partial, 'CR'));
                        const irsvdst = this.severityDistance('IR', this.getReal('IR'), getValue(partial, 'IR'));
                        const arsvdst = this.severityDistance('AR', this.getReal('AR'), getValue(partial, 'AR'));

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
        const eq1prop = eq1svdst / (lookup.depth[1][eq1] + 1);
        const eq2prop = eq2svdst / (lookup.depth[2][eq2] + 1);
        const eq3eq6prop = eq3eq6svdst / (lookup.depth[3][eq3][eq6] + 1);
        const eq4prop = eq4svdst / (lookup.depth[4][eq4] + 1);
        const eq5prop = eq5svdst / (lookup.depth[5][eq5] + 1);

        // 1.d - Multiply maximal scoring diff. by prop. of distance
        eq1msd *= eq1prop;
        eq2msd *= eq2prop;
        eq3eq6msd *= eq3eq6prop;
        eq4msd *= eq4prop;
        eq5msd *= eq5prop;

        // 2 - Compute mean
        let mean = 0;
        if (lower != 0) {
            mean = (eq1msd + eq2msd + eq3eq6msd + eq4msd + eq5msd) / lower;
        }

        // 3 - Compute score
        return roundup(eqsv - mean);
    }
    /**
     * Gives the nomenclature of the current CVSS v4.0 object i.e. its structure
     * according to the Base, Threat and Environmental metric groups.
     * 
     * @return The nomenclature string.
     */
    Nomenclature(): string {
        const isDefined = ((metric: string): boolean => this.Get(metric) != 'X');
        const t = (['E']).some(isDefined);
        const e = (['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA']).some(isDefined);

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

    private getReal(metric): string {
        if (['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'].includes(metric)) {
            const v = this.Get('M' + metric);
            if (v != 'X') {
                return v
            }
            return this.Get(metric);
        }
        const v = this.Get(metric);
        if (v != 'X') {
            return v
        }
        // If it was not a base metric then defaults
        switch (metric) {
            case 'CR':
            case 'IR':
            case 'AR':
                return 'H';
            case 'E':
                return 'A';
        }
    }
    private macrovector(): string {
        const av = this.getReal('AV');
        const ac = this.getReal('AC');
        const at = this.getReal('AT');
        const pr = this.getReal('PR');
        const ui = this.getReal('UI');
        const vc = this.getReal('VC');
        const vi = this.getReal('VI');
        const va = this.getReal('VA');
        const sc = this.getReal('SC');
        const si = this.getReal('SI');
        const sa = this.getReal('SA');
        const e = this.getReal('E');
        const cr = this.getReal('CR');
        const ir = this.getReal('IR');
        const ar = this.getReal('AR');

        // Compte MacroVectors
        // => EQ1
        let eq1 = '0';
        if (av == 'N' && pr == 'N' && ui == 'N') {
            eq1 = '0';
        } else if ((av == 'N' || pr == 'N' || ui == 'N') && !(av == 'N' && pr == 'N' && ui == 'N') && !(av == 'P')) {
            eq1 = '1';
        } else if (av == 'P' || !(av == 'N' || pr == 'N' || ui == 'N')) {
            eq1 = '2';
        }

        // EQ2
        let eq2 = '0';
        if (!(ac == 'L' && at == 'N')) {
            eq2 = '1';
        }

        // EQ3
        let eq3 = '0';
        if (vc == 'H' && vi == 'H') {
            eq3 = '0';
        } else if (!(vc == 'H' && vi == 'H') && (vc == 'H' || vi == 'H' || va == 'H')) {
            eq3 = '1';
        } else if (!(vc == 'H' || vi == 'H' || va == 'H')) {
            eq3 = '2';
        }

        // EQ4
        let eq4 = '0';
        if (si == 'S' || sa == 'S') {
            eq4 = '0';
        } else if (!(si == 'S' || sa == 'S') && (sc == 'H' || si == 'H' || sa == 'H')) {
            eq4 = '1';
        } else if (!(si == 'S' || sa == 'S') && !(sc == 'H' || si == 'H' || sa == 'H')) {
            eq4 = '2';
        }

        // EQ5
        let eq5 = '0';
        if (e == 'A' || e == 'X') {
            eq5 = '0';
        } else if (e == 'P') {
            eq5 = '1';
        } else if (e == 'U') {
            eq5 = '2';
        }

        // EQ6
        let eq6 = '0';
        const crh = (cr == 'H' || cr == 'X');
        const irh = (ir == 'H' || ir == 'X');
        const arh = (ar == 'H' || ar == 'X');
        if ((crh && vc == 'H') || (irh && vi == 'H') || (arh && va == 'H')) {
            eq6 = '0';
        } else if (!(crh && vc == 'H') && !(irh && vi == 'H') && !(arh && va == 'H')) {
            eq6 = '1';
        }

        return eq1 + eq2 + eq3 + eq4 + eq5 + eq6;
    }
    private severityDistance(metric: string, vecVal: string, mxVal: string): number {
        const values = lookup.sevIdx[metric];
        return values.indexOf(vecVal) - values.indexOf(mxVal);
    }
};

const getValue = function (partial: string, metric: string) {
    const pts = partial.split('/');
    for (const pt of pts) {
        let pts = pt.split(':')
        if (pts[0] == metric) {
            return pts[1];
        }
    }
}

const roundup = function (score: number) {
    return +(score.toFixed(1));
}

/**
 * Give the corresponding rating of the provided score.
 * 
 * @param score The score to rate. 
 * @return The rating.
 * @throws When the score is out of bounds.
 */
export const Rating = function (score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' {
    if (score < 0 || score > 10) {
        throw new Error('score out of bounds');
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

import * as errors from './errors';

// https://go.dev/play/p/FpbKl0gOmWy
const re = /^(AV:[LAN])\/(AC:[LMH])\/(Au:[MSN])\/(C:[NPC])\/(I:[NPC])\/(A:[NPC])(?:\/(E:(?:ND|U|POC|F|H))\/(RL:(?:ND|OF|TF|W|U))\/(RC:(?:ND|UC|UR|C)))?(?:\/(CDP:(?:ND|N|L|LM|MH|H))\/(TD:(?:ND|N|L|M|H))\/(CR:(?:ND|L|M|H))\/(IR:(?:ND|L|M|H))\/(AR:(?:ND|L|M|H)))?$/g;

/**
 * Implementation of the CVSS v2.0 specification (https://www.first.org/cvss/v2/guide).
 */
export class CVSS20 {
    private _metrics = {
        // Set default values of non-mandatory metrics : Not Defined (ND)
        // => Temporal
        'E': 'ND', 'RL': 'ND', 'RC': 'ND',
        // => Environmental
        'CDP': 'ND', 'TD': 'ND', 'CR': 'ND', 'IR': 'ND', 'AR': 'ND',
    };

    /**
     * Construct a CVSS v2.0 object, and parse the vector if provided.
     * If not, the Base metrics is set to the default values (score = 0).
     * 
     * @param vector The vector to parse.
     * @throws When the vector is invalid.
     */
    constructor(vector = 'AV:L/AC:L/Au:M/C:N/I:N/A:N') {
        this.parse(vector);
    }

    /**
     * Parse the provided vector.
     * 
     * @param vector The vector to parse.
     * @throws When the vector is invalid.
     */
    private parse(vector: string) {
        // Ensure input is valid according to the regular expression
        let matches = vector.matchAll(re).next().value;
        if (matches == undefined) {
            throw new Error('invalid CVSS v2.0 vector');
        }
        // Skip complete match
        matches.shift();
        // Parse each metric group
        for (let match of matches) {
            if (match == undefined) {
                continue;
            }
            const pts = match.split(':');
            this._metrics[pts[0]] = pts[1];
        }
    }

    /**
     * Return the vector string representation of the CVSS v2.0 object.
     * 
     * @return The vector string representation.
     */
    Vector() {
        let vector = '';
        const app = (metric: string) => { vector += '\/' + metric + ':' + this._metrics[metric] };
        const def = (metric: string) => { this._metrics[metric] != 'ND' };
        ['AV', 'AC', 'Au', 'C', 'I', 'A'].forEach(app);
        if (['E', 'RL', 'RC'].some(def)) {
            ['E', 'RL', 'RC'].forEach(app);
        }
        if (['CDP', 'TD', 'CR', 'IR', 'AR'].some(def)) {
            ['CDP', 'TD', 'CR', 'IR', 'AR'].forEach(app);
        }
        return vector.slice(1);
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
            throw new errors.InvalidMetric('2.0', metric)
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
        const values: [string] = metrics[metric];
        if (values == undefined) {
            throw new errors.InvalidMetric('2.0', metric);
        }
        if (!values.includes(value)) {
            throw new errors.InvalidMetricValue('2.0', metric, value);
        }
        this._metrics[metric] = value;
    }

    /**
     * Compute the CVSS v2.0 Impact score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 20.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    Impact(): number {
        const c = scores['CIA'][this._metrics['C']];
        const i = scores['CIA'][this._metrics['I']];
        const a = scores['CIA'][this._metrics['A']];
        return 10.41 * (1 - (1 - c) * (1 - i) * (1 - a));
    }

    /**
     * Compute the CVSS v2.0 Exploitability score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 20.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    Exploitability(): number {
        const av = scores['AV'][this._metrics['AV']];
        const ac = scores['AC'][this._metrics['AC']];
        const au = scores['Au'][this._metrics['Au']];
        return 20 * av * ac * au;
    }

    /**
     * Compute the CVSS v2.0 Base score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 20.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    BaseScore(): number {
        const impact = this.Impact();
        let fimpact = 0;
        if (impact != 0) {
            fimpact = 1.176;
        }
        const exploitability = this.Exploitability();
        return CVSS20.roundTo1Decimal(((0.6 * impact) + (0.4 * exploitability) - 1.5) * fimpact)
    }

    /**
     * Compute the CVSS v2.0 Temporal score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 20.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    TemporalScore(): number {
        const e = scores['E'][this._metrics['E']];
        const rl = scores['RL'][this._metrics['RL']];
        const rc = scores['RC'][this._metrics['RC']];
        return CVSS20.roundTo1Decimal(this.BaseScore() * e * rl * rc);
    }

    /**
     * Compute the CVSS v2.0 Environmental score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 20.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    EnvironmentalScore(): number {
        const c = scores['CIA'][this._metrics['C']];
        const i = scores['CIA'][this._metrics['I']];
        const a = scores['CIA'][this._metrics['A']];
        const cr = scores['CIAR'][this._metrics['CR']];
        const ir = scores['CIAR'][this._metrics['IR']];
        const ar = scores['CIAR'][this._metrics['AR']];
        const adujstedImpact = Math.min(10, 10.41 * (1 - (1 - c * cr) * (1 - i * ir) * (1 - a * ar)));
        let fimpacBase = 0;
        if (adujstedImpact != 0) {
            fimpacBase = 1.176;
        }
        const expltBase = this.Exploitability();
        const e = scores['E'][this._metrics['E']];
        const rl = scores['RL'][this._metrics['RL']];
        const rc = scores['RC'][this._metrics['RC']];
        const recBase = CVSS20.roundTo1Decimal(((0.6 * adujstedImpact) + (0.4 * expltBase) - 1.5) * fimpacBase);
        const adjustedTemporal = CVSS20.roundTo1Decimal(recBase * e * rl * rc);
        const cdp = scores['CDP'][this._metrics['CDP']];
        const td = scores['TD'][this._metrics['TD']];
        return CVSS20.roundTo1Decimal((adjustedTemporal + (10 - adjustedTemporal) * cdp) * td);
    }

    private static roundTo1Decimal(x: number): number {
        return Math.round(x * 10) / 10
    }
}

const metrics = {
    // Base
    'AV': ['L', 'A', 'N'],
    'AC': ['L', 'M', 'H'],
    'Au': ['M', 'S', 'N'],
    'C': ['N', 'P', 'C'],
    'I': ['N', 'P', 'C'],
    'A': ['N', 'P', 'C'],
    // Temporal
    'E': ['ND', 'U', 'POC', 'F', 'H'],
    'RL': ['ND', 'OF', 'TF', 'W', 'U'],
    'RC': ['ND', 'UC', 'UR', 'C'],
    // Environmental
    'CDP': ['ND', 'N', 'L', 'LM', 'MH', 'H'],
    'TD': ['ND', 'N', 'L', 'M', 'H'],
    'CR': ['ND', 'L', 'M', 'H'],
    'IR': ['ND', 'L', 'M', 'H'],
    'AR': ['ND', 'L', 'M', 'H'],
};

const scores = {
    'AV': {
        'L': 0.395,
        'A': 0.646,
        'N': 1.0,
    },
    'AC': {
        'H': 0.35,
        'M': 0.61,
        'L': 0.71,
    },
    'Au': {
        'M': 0.45,
        'S': 0.56,
        'N': 0.704,
    },
    'CIA': {
        'N': 0.0,
        'P': 0.275,
        'C': 0.660,
    },
    'E': {
        'U': 0.85,
        'POC': 0.9,
        'F': 0.95,
        'H': 1.0,
        'ND': 1.0,
    },
    'RL': {
        'OF': 0.87,
        'TF': 0.90,
        'W': 0.95,
        'U': 1.0,
        'ND': 1.0,
    },
    'RC': {
        'UC': 0.90,
        'UR': 0.95,
        'C': 1.0,
        'ND': 1.0,
    },
    'CDP': {
        'N': 0,
        'ND': 0,
        'L': 0.1,
        'LM': 0.3,
        'MH': 0.4,
        'H': 0.5,
    },
    'TD': {
        'N': 0,
        'L': 0.25,
        'M': 0.75,
        'H': 1.0,
        'ND': 1.0,
    },
    'CIAR': {
        'L': 0.5,
        'M': 1.0,
        'ND': 1.0,
        'H': 0.51,
    },
};

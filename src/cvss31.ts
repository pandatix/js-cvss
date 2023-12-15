import * as errors from './errors';

const cvss31header = 'CVSS:3.1/'

/**
 * Implementation of the CVSS v3.1 specification (https://www.first.org/cvss/v3.1/specification-document).
 */
export class CVSS31 {
    private _metrics = {
        // Set default values of non-mandatory metrics : Not Defined (X)
        // => Temporal
        'E': 'X', 'RL': 'X', 'RC': 'X',
        // => Environmental
        'CR': 'X', 'IR': 'X', 'AR': 'X', 'MAV': 'X', 'MAC': 'X', 'MPR': 'X', 'MUI': 'X', 'MS': 'X', 'MC': 'X', 'MI': 'X', 'MA': 'X'
    }

    /**
     * Construct a CVSS v3.1 object, and parse the vector if provided.
     * If not, the Base metrics is set to the default values (score = 0).
     * 
     * @param vector The vector to parse.
     * @throws When the vector is invalid.
     */
    constructor(vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N') {
        this.parse(vector);
    }

    /**
     * Parse the provided vector.
     * 
     * @param vector The vector to parse.
     * @throws When the vector is invalid.
     */
    private parse(vector: string) {
        // Check header
        if (!vector.startsWith(cvss31header)) {
            throw new Error('invalid vector')
        }
        vector = vector.substring(cvss31header.length)

        // Parse vector
        let kvm = {};
        let metrics = vector.split('/');
        for (let metric of metrics) {
            let pts = metric.split(':');
            if (pts.length != 2) {
                throw new Error('invalid vector')
            }
            if (kvm[pts[0]] != undefined) {
                throw new Error('metric ' + pts[0] + ' already defined');
            }
            kvm[pts[0]] = pts[1];
            this.Set(pts[0], pts[1]);
        }

        // Check all mandatory metrics are defined
        if (['AV', 'AC', 'AT', 'PR', 'UI', 'S', 'C', 'I', 'A'].some((metric) => { this._metrics[metric] == undefined })) {
            throw new Error('all mandatory metrics are not provided');
        }
    }

    /**
     * Return the vector string representation of the CVSS v3.1 object.
     * 
     * @return The vector string representation.
     */
    Vector() {
        let vector = 'CVSS:3.1';
        for (let metric in Object.entries(this._metrics)) {
            let value = this.Get(metric);
            if (value == 'X') {
                continue
            }
            vector += '/' + metric + ':' + value;
        }
        return vector
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
            throw new errors.InvalidMetric('3.1', metric);
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
        if (metricValues[metric] == undefined) {
            throw new errors.InvalidMetric('3.1', metric);
        }
        if (!metricValues[metric].includes(value)) {
            throw new errors.InvalidMetricValue('3.1', metric, value);
        }
        this._metrics[metric] = value;
    }

    /**
     * Compute the CVSS v3.1 Impact of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 31.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    Impact(): number {
        const c = scores['CIA'][this._metrics['C']];
        const i = scores['CIA'][this._metrics['I']];
        const a = scores['CIA'][this._metrics['A']];
        const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
        if (this._metrics['S'] == 'U') {
            return 6.42 * iss;
        }
        return 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
    }

    /**
     * Compute the CVSS v3.1 Exploitability of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 31.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    Exploitability(): number {
        const av = scores['AV'][this._metrics['AV']];
        const ac = scores['AC'][this._metrics['AC']];
        const pr = scores['PR'][this._metrics['PR']][this._metrics['S']];
        const ui = scores['UI'][this._metrics['UI']];
        return 8.22 * av * ac * pr * ui
    }

    /**
     * Compute the CVSS v3.1 Base Score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 31.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    BaseScore(): number {
        const impact = this.Impact();
        const exploitability = this.Exploitability();
        if (impact <= 0) {
            return 0
        }
        if (this._metrics['S'] == 'U') {
            return CVSS31.roundup(Math.min(impact + exploitability, 10));
        }
        return CVSS31.roundup(Math.min(1.08 * (impact + exploitability), 10));
    }

    /**
     * Compute the CVSS v3.1 Temporal Score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 31.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    TemporalScore(): number {
        const e = scores['E'][this._metrics['E']];
        const rl = scores['RL'][this._metrics['RL']];
        const rc = scores['RC'][this._metrics['RC']];
        return CVSS31.roundup(this.BaseScore() * e * rl * rc);
    }

    /**
     * Compute the CVSS v3.1 Environmental Score of the current object, given its metrics and their
     * corresponding values.
     * 
     * The implementation internals are largely based upon https://github.com/pandatix/go-cvss
     * submodule 31.
     * 
     * @return The score (between 0.0 and 10.0 both included).
     */
    EnvironmentalScore(): number {
        const mav = scores['AV'][this.getReal('AV')];
        const mac = scores['AC'][this.getReal('AC')];
        const mpr = scores['PR'][this.getReal('PR')][this._metrics['S']];
        const mui = scores['UI'][this.getReal('UI')];
        const s = this.getReal('S');
        const c = scores['CIA'][this.getReal('C')];
        const i = scores['CIA'][this.getReal('I')];
        const a = scores['CIA'][this.getReal('A')];
        const cr = scores['CIAR'][this._metrics['CR']];
        const ir = scores['CIAR'][this._metrics['IR']];
        const ar = scores['CIAR'][this._metrics['AR']];
        const e = scores['E'][this._metrics['E']];
        const rl = scores['RL'][this._metrics['RL']];
        const rc = scores['RC'][this._metrics['RC']];

        const miss = Math.min(1 - (1 - cr * c) * (1 - ir * i) * (1 - ar * a), 0.915);
        let modifiedImpact: number;
        if (s == 'U') {
            modifiedImpact = 6.42 * miss;
        } else {
            modifiedImpact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13;
        }
        let modifiedExploitability = 8.22 * mav * mac * mpr * mui;
        if (modifiedImpact <= 0) {
            return 0;
        }
        if (s == 'U') {
            return CVSS31.roundup(CVSS31.roundup(Math.min(modifiedImpact + modifiedExploitability, 10)) * e * rl * rc);
        }
        return CVSS31.roundup(CVSS31.roundup(Math.min(1.08 * (modifiedImpact + modifiedExploitability), 10)) * e * rl * rc);
    }

    private getReal(metric: string): string {
        if (['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'].includes(metric)) {
            const v = this.Get('M' + metric);
            if (v != 'X') {
                return v
            }
            return this.Get(metric);
        }
        return this.Get(metric);
    }

    private static roundup(x: number): number {
        let bx = Math.round(x * 100_000);
        if (bx % 1000 == 0) {
            return bx / 100_000;
        }
        return (Math.floor(bx / 10_000) + 1) / 10
    }

    /**
     * Give the corresponding rating of the provided score.
     * 
     * @param score The score to rate. 
     * @return The rating.
     * @throws When the score is out of bounds.
     */
    public static Rating(score: number): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' {
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
}

const metricValues = {
    'AV': ['N', 'A', 'L', 'P'],
    'AC': ['L', 'H'],
    'PR': ['N', 'L', 'H'],
    'UI': ['N', 'R'],
    'S': ['U', 'C'],
    'C': ['H', 'L', 'N'],
    'I': ['H', 'L', 'N'],
    'A': ['H', 'L', 'N'],
    'E': ['X', 'H', 'F', 'P', 'U'],
    'RL': ['X', 'U', 'W', 'T', 'O'],
    'RC': ['X', 'C', 'R', 'U'],
    'CR': ['X', 'H', 'M', 'L'],
    'IR': ['X', 'H', 'M', 'L'],
    'AR': ['X', 'H', 'M', 'L'],
    'MAV': ['X', 'N', 'A', 'L', 'P'],
    'MAC': ['X', 'L', 'H'],
    'MPR': ['X', 'N', 'L', 'H'],
    'MUI': ['X', 'N', 'R'],
    'MS': ['X', 'U', 'C'],
    'MC': ['X', 'H', 'L', 'N'],
    'MI': ['X', 'H', 'L', 'N'],
    'MA': ['X', 'H', 'L', 'N'],
};

const scores = {
    'AV': {
        'N': 0.85,
        'A': 0.62,
        'L': 0.55,
        'P': 0.2,
    },
    'AC': {
        'L': 0.77,
        'H': 0.44,
    },
    'PR': {
        'N': {
            'U': 0.85,
            'C': 0.85,
        },
        'L': {
            'U': 0.62,
            'C': 0.68,
        },
        'H': {
            'U': 0.27,
            'C': 0.5,
        },
    },
    'UI': {
        'N': 0.85,
        'R': 0.62,
    },
    'CIA': {
        'H': 0.56,
        'L': 0.22,
        'N': 0,
    },
    'E': {
        'X': 1,
        'H': 1,
        'F': 0.97,
        'P': 0.94,
        'U': 0.91,
    },
    'RL': {
        'X': 1,
        'U': 1,
        'W': 0.97,
        'T': 0.96,
        'O': 0.95,
    },
    'RC': {
        'X': 1,
        'C': 1,
        'R': 0.96,
        'U': 0.92,
    },
    'CIAR': {
        'X': 1,
        'M': 1,
        'H': 1.5,
        'L': 0.5,
    },
};

export class InvalidMetric extends Error {
    constructor(public version: string, public metric: string) {
        super('invalid CVSS v' + version + ' metric ' + metric);
    }
}

export class InvalidMetricValue extends Error {
    constructor(public version: string, public metric: string, public value: string) {
        super('invalid CVSS v' + version + ' value ' + value + ' for metric ' + metric);
    }
}

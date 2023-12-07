export class InvalidMetric extends Error {
    metric: string;

    constructor(metric: string) {
        super('invalid CVSS v4.0 metric ' + metric);
        this.metric = metric;
    }
}

export class InvalidMetricValue extends Error {
    metric: string;
    value: string;

    constructor(metric: string, value: string) {
        super('invalid CVSS v4.0 value ' + value + ' for metric ' + metric);
        this.metric = metric;
        this.value = value;
    }
}

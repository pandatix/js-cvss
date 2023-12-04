const InvalidVector = new Error('invalid CVSS v4.0 vector');
const OutOfBoundsScore = new Error('score out of bounds');

class InvalidMetric {
    constructor(metric) {
        this.metric = metric;
    }
    String() {
        return 'invalid CVSS v4.0 metric '+ this.metric;
    }
}

class InvalidMetricValue {
    constructor(metric, value) {
        this.metric = metric;
        this.value = value;
    }
    String() {
        return 'invalid CVSS v4.0 value ' + this.value + ' for metric ' + this.metric;
    }
}

module.exports = { InvalidVector, OutOfBoundsScore, InvalidMetric, InvalidMetricValue };

class ForEachValues {
    static function main() {
        var sum = 0;
        for (v in [1, 2, 3, 4]) {
            sum += v;
        }
        trace(sum);
    }
}

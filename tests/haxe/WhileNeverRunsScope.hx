class WhileNeverRunsScope {
    static function main() {
        var i = 0;
        var last = -1;
        while (i > 10) {
            var x = i * 2;
            last = x;
            i++;
        }
        trace(last);
        trace(i);

        var found = null;
        var items = [1, 2, 3];
        var idx = 0;
        while (idx > 100) {
            var cand = items[idx];
            if (cand == 2) {
                found = cand;
                break;
            }
            idx++;
        }
        trace(found);

        var acc = 0;
        for (i in 0...0) {
            acc += i;
        }
        trace(acc);
    }
}

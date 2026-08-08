class LoopIterRegisterReuse {
    static function run(): Int {
        var total = 0;
        var i = 0;
        while (i < 5) {
            if (i % 2 == 0) {
                var tmp = i * 10;
                total += tmp;
            } else {
                var tmp2 = i * 1000;
                total += tmp2;
            }
            i++;
        }
        return total;
    }

    static function main() {
        trace(run());
    }
}

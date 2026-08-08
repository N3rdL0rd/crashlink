class TryFinallyPaths {
    static function risky(x: Int): Int {
        try {
            if (x == 0) {
                throw "boom";
            }
            return Std.int(10 / x);
        } catch (e: Dynamic) {
            return -1;
        }
    }

    static function withFinally(x: Int): Int {
        var result = 0;
        try {
            if (x == 0) throw "boom";
            result = Std.int(100 / x);
        } catch (e: Dynamic) {
            result = -1;
        }
        return result;
    }

    static function main() {
        trace(risky(2));
        trace(risky(0));
        trace(withFinally(5));
        trace(withFinally(0));
    }
}

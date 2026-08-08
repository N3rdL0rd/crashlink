class RegTypeSwap {
    static function compute(n:Int):Int {
        return n * 2 + 1;
    }

    static function main() {
        var n = 41;
        var i = compute(n);
        Sys.println(i);
        // i (Int) last use above; now reuse same slot conceptually for a String
        var s = "value=" + Std.string(i);
        Sys.println(s);
        if (i > 0) {
            var s2 = s + "!";
            Sys.println(s2);
        }
    }
}

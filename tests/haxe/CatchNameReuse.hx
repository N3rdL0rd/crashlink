class CatchNameReuse {
    static function risky(n: Int): Int {
        if (n == 0) throw "zero error";
        if (n == 1) throw 42;
        return n * 2;
    }

    static function main() {
        try {
            risky(0);
        } catch (e: String) {
            Sys.println("string catch: " + e);
        }

        try {
            risky(1);
        } catch (e: Dynamic) {
            Sys.println("dynamic catch: " + Std.string(e));
        }

        var e = "outer";
        try {
            risky(0);
        } catch (e: String) {
            Sys.println("inner: " + e);
        }
        Sys.println("outer after: " + e);
    }
}
